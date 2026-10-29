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
#     (`src/shared/runtime-terminal-send-contract.ts:12` at v1.4.229 and v1.4.238 — the old
#     `runtime-terminal-contracts.ts:221-225` anchor had gone stale). v4's blind re-Enter/heartbeat loop is DELETED:
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
#   - PROFILE=ro NEVER takes worker-start on Orca (off Orca the provider builds ro from --profile,
#     so ro rides worker-start there): launch args come from the host's stored permission
#     choice for the agent (from v1.4.239 own / ask / accept-edits / auto / full-access, its
#     flag before `agentDefaultArgs`: `tui-agent-launch-defaults.ts:165-179`). full-access IS the
#     YOLO map, as is an older host's migrated default (`tui-agent-launch-defaults.ts:37-38`
#     re-exports `YOLO_TUI_AGENT_ARGS` as `DEFAULT_TUI_AGENT_ARGS`), so such a host would
#     silently upgrade a read-only reviewer to a bypass one. Every other choice carries no
#     PROFILE flag (auto is claude `--permission-mode auto` / codex `--approve-for-me`,
#     `AUTO_TUI_AGENT_ARGS`, `tui-agent-permissions.ts:6-10`), so exit 5 refuses it (re-witness:
#     docs/runs/2026-10-26-pin-it-239.md). The rationale is host-dependent, not universal. `agentDefaultArgs` is
#     source-witnessed at v1.4.203 (`tui-agent-launch-defaults.ts:10`); live probe owed — pin-it.
#   - `launch.effective` from the worker-start receipt is printed when present: never claim a model,
#     effort, or permission flag from the REQUESTED arguments alone
#     (`orchestration/coordinator-loop:23-36`).
#   - fail-closed: any failed step exits nonzero with a SPAWN=FAILED diagnostic line on stderr
#   - respects the task DAG: never forces `ready`; `--mark-ready` is an explicit opt-in and
#     only applies when every declared dep is already completed
#   - least-privilege launch profiles: PROFILE=ro|rw|danger; on Orca, danger is refused until
#     authoritative prelaunch placement binding to the validated disposable sandbox is supported.
#     A non-Orca runtime runs the SAME `vm recipe doctor` through orca_cli.py; danger proceeds there
#     only when the clear transcript is a portable backend proving isolation AND prelaunch
#     placement (sandbox_doctor.py --require-placement, #585). Non-Orca launches come from
#     runtime/providers/base.py build_harness_command — one launch table (#580).
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
#   agent ∈ claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity|jcode|goose|hermes|crush (default claude),
#           or openhands, the OpenHands SDK agent, on OPEN_FLEET_RUNTIME=openhands only (#596)
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
# `tui-agent-permissions.ts:12-45` at the v1.4.239 pin and v1.4.238, 6-39 at v1.4.229 — the map is
# unchanged across that range — so workers never block on a prompt; anything else fails closed
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
#                         `--dangerously-skip-permissions` (`tui-agent-launch-defaults.ts:23-26`);
#                         kilo stays off this roster for the same reason opencode fails closed.
#   jcode/goose/hermes  → ro + rw + danger; the ro rows are this script's own, carrying base.py's
#                         ro restriction (#596). crush → rw + danger; ro → WORKER_CMD (its
#                         read-only mode is a data-dir config no Orca lane installs).
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
#   Each ORCA_* name below is the legacy alias of its OPEN_FLEET_* twin (same suffix), which is
#   read first: the ORCA_* value applies only when the twin is unset or empty, and off Orca two
#   SANDBOX_RECIPE values that disagree are refused.
#   SP                        parent dir for retained per-attempt JSON artifacts (default: cwd)
#   PROFILE                   ro | rw (default) | danger — worker permission profile
#   ORCA_COORD_ALLOW_AUTONOMOUS_WRITE  must be 1 for PROFILE=rw (accept autonomous bypass workers)
#   ORCA_DENY_HOOK_SETTINGS   settings file registering deny-hook.sh for workers; named →
#                             verified armed (registration + live deny probe) or the spawn
#                             refuses, for EVERY profile incl. ro (W4-06). Unset → the posix and
#                             openhands providers install AND verify the guard before the agent
#                             starts, so the spawn proceeds; another non-Orca provider proceeds
#                             with an UNVERIFIED warning; on Orca (no open-fleet guard in
#                             worker-start) it REFUSES, every profile, unless the opt-out below
#                             is set
#   ORCA_ALLOW_UNVERIFIED_DENY_HOOK  the Orca-lane opt-out: 1 lets an unset-guard spawn proceed
#                             with an UNVERIFIED warning (W4-06). Off Orca it is not needed
#   ORCA_REQUIRE_DENY_HOOK    1 (hardened coordinator): an unset ORCA_DENY_HOOK_SETTINGS always
#                             refuses, on every runtime, before any provider deferral or opt-out
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
#   SUBMIT_SECS               how long terminal send waits to observe the submit (default 30) — the
#                             ro claude no-inject fallback (#680).
#   RESERVATION_WAIT_SECS     how long a session nothing identifies waits for open launch
#                             reservations to resolve before it is capped at them (default 120;
#                             0 caps at once). Lowering it only caps sooner (W4-04).
#   SPAWN_ROOT_WAIT_SECS      how long registration looks for the process carrying a new pane's
#                             handle (default 1). Lowering it only gives up sooner, which keeps
#                             the launch reservation (W4-04).
set -Eeuo pipefail  # -E: ERR trap fires inside functions (orca_json) too
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  # sibling scripts (sandbox_doctor.py)
# The CLI command name, resolved the way upstream documents it (#510): ORCA_CLI_COMMAND when set,
# else orca-dev in a dev checkout, else orca-ide on Linux (bare `orca` there is the GNOME screen
# reader), else orca. One resolver for every fleet script: runtime/scripts/orca_cli.py.
step=resolve-cli
task="?"
trap 'rc=$?; echo "SPAWN=FAILED task=${task} step=${step} rc=${rc}" >&2; exit "${rc}"' ERR
if ! ORCA_BIN="$(python3 -I "$HERE/orca_cli.py")"; then
  echo "SPAWN=REFUSED task=? the runtime CLI could not be resolved (OPEN_FLEET_RUNTIME / OPEN_FLEET_CLI_COMMAND / ORCA_CLI_COMMAND; see runtime/scripts/orca_cli.py)" >&2
  exit 2
fi
step=parse-args

# inert_text: stdin as ONE inert line, every unprintable character (line breaks, ESC, CR, bidi)
# escaped, for runtime text spliced into a SPAWN= line (W4-11 class, Codex round 2 sweep).
inert_text() {
  python3 -I -c 'import sys
t = sys.stdin.buffer.read().decode("utf-8", "replace")
sys.stdout.write("".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in t))'
}

# JSON_STRICT_PY: the one way a runtime response is read here (Codex round 5). json.load keeps the
# LAST of two equal keys, so a response could name one pane to the registry and another to the
# reader that judged it; NaN, Infinity and a number that overflows to inf are not JSON either.
# strict_load / strict_loads raise Ambiguous (a ValueError) on each of those and on bytes that
# are not UTF-8, so every reader below takes its own unparseable path, which fails closed.
# (receipt_handles reads every occurrence instead: it must still find a handle in such a response.)
JSON_STRICT_PY='import json, math, sys
class Ambiguous(ValueError):
    pass
def _strict_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Ambiguous(f"duplicate key {k!r}")
        out[k] = v
    return out
def _strict_constant(c):
    raise Ambiguous(f"non-JSON constant {c}")
def _strict_float(s):
    f = float(s)
    if not math.isfinite(f):
        raise Ambiguous(f"number out of range: {s[:40]}")
    return f
def strict_loads(text):
    return json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_strict_constant,
                      parse_float=_strict_float)
def strict_load(path):
    with open(path, "rb") as fh:
        return strict_loads(fh.read().decode("utf-8"))
'
# pyjson ARGS... <<'PY' — python3 -I running the program on stdin, with JSON_STRICT_PY loaded.
pyjson() {
  python3 -I -c "${JSON_STRICT_PY}"'
exec(compile(sys.stdin.read(), "<spawn_worker.sh>", "exec"))' "$@"
}

# orca_json <outfile> <orca-args...> — run orca with --json, fail on nonzero exit
# OR on an exit-0 error envelope ({"error": ...}); fail-closed for every step.
orca_json() {
  local out="$1"; shift
  "$ORCA_BIN" "$@" --json > "$out"
  envelope_check "$out"
}
# envelope_check <file>: fail (exit 1, the error printed inert) on an error envelope, and on a
# response that is not one unambiguous JSON document.
envelope_check() {
  pyjson "$1" <<'PY'
import json, sys
def _f(v):
    """A receipt field, inert and on one line (W4-11): anything unprintable escaped."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(v))
try:
    d = strict_load(sys.argv[1])
except ValueError as exc:
    print(f"orca response is not one unambiguous JSON document: {_f(exc)}", file=sys.stderr)
    raise SystemExit(1)
err = None
if isinstance(d, dict):
    err = d.get("error")
    res = d.get("result")
    if not err and isinstance(res, dict):
        err = res.get("error")
if err:
    print(f"orca error envelope: {_f(err)}", file=sys.stderr)
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
    --) shift; while [ $# -gt 0 ]; do args+=("$1"); shift; done ;;
    -*)
      echo "SPAWN=REFUSED task=? unknown flag '$1' (it is not a task id; see the Options in this script's header)" >&2
      exit 2 ;;
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
# The harness: the positional [agent], else OPEN_FLEET_HARNESS (the knob README and
# docs/concepts.md name; it was documented but read nowhere, 2026-10-26 review), else claude.
default_agent="${OPEN_FLEET_HARNESS:-claude}"
if [ "$SPEC_GIVEN" = "1" ]; then
  task=""; sel="${args[0]:-}"; title="${args[1]:-}"; agent="${args[2]:-$default_agent}"; effort="${args[3]:-xhigh}"
else
  task="${args[0]:-}"; sel="${args[1]:-}"; title="${args[2]:-}"; agent="${args[3]:-$default_agent}"; effort="${args[4]:-xhigh}"
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
  if ! printf '%s' "$DEPS" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d,list) and all(isinstance(x,str) for x in d) else 1)' 2>/dev/null; then
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
for pair in "RUN_GIVEN:RUN_ID:--run" "FROM_GIVEN:FROM_HANDLE:--from" \
            "RETRY_OF_GIVEN:RETRY_OF:--retry-of" "RETRY_REQ_GIVEN:RETRY_REQUEST:--retry-request" \
            "ON_GIVEN:ON_ENV:--on" "ENV_GIVEN:ROUTE_ENV:--environment" \
            "PAIRING_GIVEN:ROUTE_PAIRING:--pairing-code"; do
  # Variable NAMES, dereferenced: splitting the value itself on ':' read `--run :abc` as empty.
  flagvar="${pair%%:*}"; rest="${pair#*:}"; valvar="${rest%%:*}"; name="${rest##*:}"
  given="${!flagvar}"; val="${!valvar}"
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
# `openhands` is no CLI harness: it is the OpenHands SDK agent, which only the openhands runtime
# runs (checked once the runtime is resolved, below).
case "$agent" in
  claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity|jcode|goose|hermes|crush|openhands) : ;;
  *)
    echo "SPAWN=REFUSED task=${task} unknown agent '${agent}' (want claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity|jcode|goose|hermes|crush, or openhands on the openhands runtime)" >&2
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
SUBMIT_SECS="${SUBMIT_SECS:-30}"
# The runtime, resolved by the SAME rule the providers use (runtime/providers/__init__.py
# active_provider_name): case- and space-insensitive, local-posix → posix, auto → orca only when
# the Orca CLI is on PATH. A raw string compare read OPEN_FLEET_RUNTIME=ORCA as a non-Orca
# runtime and swapped in the wrong launch table and danger rules.
if ! ACTIVE_RUNTIME=$(python3 -I - "$HERE/../.." <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from runtime.providers import ProviderError, active_provider_name
try:
    print(active_provider_name())
except ProviderError as err:
    print("".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(err.message)), file=sys.stderr)
    raise SystemExit(2)
PY
); then
  echo "SPAWN=REFUSED task=${tname} unknown runtime OPEN_FLEET_RUNTIME/ORCA_FLEET_RUNTIME — see runtime/providers/__init__.py" >&2
  exit 2
fi
# The openhands runtime runs its own SDK agent whatever name it is handed: `claude` there printed a
# claude launch, started an OpenHands conversation, then read LAUNCHED_UNUSABLE off the receipt.
# capabilities.json claims exactly that pairing, so the wrapper launches exactly that one (#596).
if [ "$agent" = "openhands" ] && [ "$ACTIVE_RUNTIME" != "openhands" ]; then
  echo "SPAWN=REFUSED task=${tname} agent 'openhands' is the OpenHands SDK agent, which only the openhands runtime runs (OPEN_FLEET_RUNTIME=openhands); the active runtime is '${ACTIVE_RUNTIME}'" >&2
  exit 2
fi
if [ "$ACTIVE_RUNTIME" = "openhands" ] && [ "$agent" != "openhands" ]; then
  echo "SPAWN=REFUSED task=${tname} the openhands runtime runs only its own OpenHands SDK agent: agent '${agent}' would start an OpenHands conversation, not ${agent} — pass the agent openhands" >&2
  exit 2
fi
# The parent profile a child must not exceed is the MOST restrictive of every source that
# names one: the --parent-profile flag, the inherited OPEN_FLEET_PARENT_PROFILE /
# ORCA_PARENT_PROFILE, the CALLER's own OPEN_FLEET_SANDBOX_PROFILE / ORCA_SANDBOX_PROFILE (posix
# exports both into every worker), and the profile this script RECORDED for the caller's pane.
# Taking the first non-empty one let a ro worker mint an rw child by passing --parent-profile rw,
# or by naming none at all (G14).
profile_rank() { case "$1" in ro) echo 0 ;; rw) echo 1 ;; danger) echo 2 ;; *) echo x ;; esac; }
# W4-04: the spawn registry. Nothing exported a profile into an Orca worker, and a `VAR=val`
# prefix on its launch command is neither shell-neutral (PowerShell, cmd.exe and nushell are in
# Orca's --shell keyset) nor available to worker-start, so every launch below is RECORDED here
# under the pane handle Orca (or posix) gives the worker, which its pane then carries as
# ORCA_TERMINAL_HANDLE. A spawn from a recorded pane is capped at that record; an empty record
# fails safe (ro), a foreign value refuses.
# The ABSENCE of a record never reads as uncapped for a session that may be a worker (Codex rounds
# 2 and 3). The worker's command runs before its handle is known (terminal create and worker-start
# both return it after starting the command), so each launch first RESERVES its profile in
# .pending/ (`<profile> <launcher pane> <launcher pid> <launcher start>`); a launch whose
# reservation cannot be written is refused. And a harness may drop ORCA_* from the worker's shell
# (Codex's shell_environment_policy does), so the handle is not the only identity: registration
# also records the worker's pane ROOT process by pid and start time (spawn_identity.py, found by
# the handle in the pane's initial environment), and a spawn walks its own ancestry, so a process
# in a ro worker's pane tree is capped at ro whatever its environment says. A session no record
# and no root identifies:
#   - waits for every open reservation it is not exempt from (RESERVATION_WAIT_SECS, default 120),
#     re-reading its identity each time, and is then capped at the most restrictive one still open;
#   - is capped at the most restrictive LIVE worker when it runs inside a provider's process tree
#     (under a recorded host: the pty host, a tmux pane) — unless it is ANCHORED: a process of the
#     coordinator that launched a worker while uncapped, which no worker can descend from. Only an
#     anchored session is exempt from a reservation, and never from one whose launch it descends
#     from. A reservation whose launcher is gone is not waited on: it was kept because its worker
#     may be live unrecorded, and it caps until removed.
# Not covered (residuals; whether any harness does one as ordinary behaviour is unwitnessed): a
# worker process outside its pane's tree — one that daemonized out of it (reparented, it descends
# from no recorded root or host, root alive or not), a command a harness runs from a process
# started outside the pane, a spawn in another pid namespace — when its environment no longer
# carries the pane handle; a worker whose HOME is not its coordinator's; a launch whose pane
# process itself carries no handle (a command that clears its environment, `env -i …`).
SPAWN_HOME="${HOME:-}"
if [ -z "$SPAWN_HOME" ]; then  # a scrubbed HOME still reads the uid's registry
  SPAWN_HOME=$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)' 2>/dev/null || true)
fi
SPAWN_REGISTRY="${SPAWN_HOME:+$SPAWN_HOME/.open-fleet/spawn-profiles}"
SPAWN_PENDING="${SPAWN_REGISTRY:+$SPAWN_REGISTRY/.pending}"
registry_key_ok() { case "$1" in ""|[!A-Za-z0-9]*|*[!A-Za-z0-9._:-]*) return 1 ;; esac; return 0; }
own_handles=()
for _ph in "${ORCA_TERMINAL_HANDLE:-}" "${OPEN_FLEET_TERMINAL_HANDLE:-}"; do
  if registry_key_ok "$_ph"; then own_handles+=("$_ph"); fi
done
# identify: registered_profiles ← this pane's handle records and every recorded root among this
# process's ancestors; plus the reservations, liveness and tree position whoami reports.
identify() {
  registered_profiles=(); open_reservations=(); open_profiles=(); live_profiles=()
  reservations_in_flight=0; in_tree=no; anchored=no; self_key=""; identity_ok=1
  [ -n "$SPAWN_REGISTRY" ] || { identity_ok=0; return 0; }
  local _out _k _a _b _c
  if ! _out=$(python3 -I "$HERE/spawn_identity.py" whoami --registry "$SPAWN_REGISTRY" --pid "$$" 2>/dev/null); then
    identity_ok=0; return 0
  fi
  while read -r _k _a _b _c; do
    case "$_k" in
      ROOT) registered_profiles+=("$_a") ;;
      LIVE) live_profiles+=("$_a") ;;
      INTREE) in_tree="$_a" ;;
      ANCHORED) anchored="$_a" ;;
      SELF) self_key="$_a" ;;
      RESERVATION)
        open_profiles+=("$_a"); open_reservations+=("$_c")
        if [ "$_b" = "1" ]; then reservations_in_flight=1; fi ;;
    esac
  done <<< "$_out"
  for _ph in ${own_handles[@]+"${own_handles[@]}"}; do
    [ -f "$SPAWN_REGISTRY/$_ph" ] || continue
    _rp=$(head -n 1 -- "$SPAWN_REGISTRY/$_ph" 2>/dev/null || true)
    registered_profiles+=("${_rp:-ro}")
  done
}
identify
if [ "$identity_ok" = "1" ] && [ "${#registered_profiles[@]}" -eq 0 ]; then
  _rwait="${RESERVATION_WAIT_SECS:-120}"
  case "$_rwait" in ""|*[!0-9]*) _rwait=120 ;; esac
  _rdeadline=$((SECONDS + _rwait))
  while [ "$identity_ok" = "1" ] && [ "${#registered_profiles[@]}" -eq 0 ] \
        && [ "$reservations_in_flight" = "1" ] && [ "$SECONDS" -lt "$_rdeadline" ]; do
    sleep 0.2
    identify
  done
fi
# The cap is a property of the FINAL identity state, the last identify()'s, whichever iteration
# that was (Codex round 5): a read that fails while waiting clears every array and sets
# identity_ok=0, and capping only on the first read let such a session launch uncapped.
if [ "$identity_ok" = "0" ]; then
  registered_profiles=(ro)
  echo "SPAWN=NOTE task=${tname} this session's spawn identity cannot be read (no registry location, or a read it needs failed: its process ancestry, the spawn registry, or a /proc that is not this pid namespace's): the child is capped at ro rather than left uncapped (W4-04)" >&2
elif [ "${#registered_profiles[@]}" -eq 0 ] && [ "${#open_reservations[@]}" -gt 0 ]; then
  registered_profiles=("${open_profiles[@]}")
  echo "SPAWN=NOTE task=${tname} this session has no spawn record, and ${#open_reservations[@]} launch(es) in the spawn registry have not recorded their worker (${open_reservations[*]}): it may be the worker one of them started, so the child is capped at the most restrictive reserved profile (W4-04). A reservation whose launcher is gone was kept because its worker may be live unrecorded; remove it once worker-list shows no such worker." >&2
elif [ "${#registered_profiles[@]}" -eq 0 ] && [ "$in_tree" = "yes" ] && [ "$anchored" = "no" ] \
     && [ "${#live_profiles[@]}" -gt 0 ]; then
  registered_profiles=("${live_profiles[@]}")
  echo "SPAWN=NOTE task=${tname} this session runs inside a provider's process tree, nothing identifies it (no spawn record, no recorded worker root among its ancestors, no coordinator anchor), and ${#live_profiles[@]} capped worker(s) are live: it is capped at the most restrictive of them rather than read as a coordinator (W4-04)" >&2
fi
known_parent() {  # refuse, in this shell (never a subshell), a parent profile outside the keyset
  if [ "$(profile_rank "$1")" = "x" ]; then
    echo "SPAWN=REFUSED task=${task} unknown parent profile '$1' (want ro|rw|danger)" >&2
    exit 2
  fi
}
fold_parent() {  # fold_parent <current> <candidate>: the more restrictive of two known profiles
  if [ -z "$1" ] || [ "$(profile_rank "$2")" -lt "$(profile_rank "$1")" ]; then echo "$2"; else echo "$1"; fi
}
env_parent=""
for _pp in "${OPEN_FLEET_PARENT_PROFILE:-}" "${ORCA_PARENT_PROFILE:-}" "${OPEN_FLEET_SANDBOX_PROFILE:-}" \
           "${ORCA_SANDBOX_PROFILE:-}" ${registered_profiles[@]+"${registered_profiles[@]}"}; do
  [ -n "$_pp" ] || continue
  known_parent "$_pp"
  env_parent=$(fold_parent "$env_parent" "$_pp")
done
# No parent profile is NOT "uncapped" inside a worker. Each of these names is fleet worker identity
# a runtime sets for the worker it launches (posix: dispatch/worker id; every base.py launch and a
# deny-hook settings file: the unit worktree), never a coordinator session; carrying one with no
# profile in the environment or the registry caps the child at ro, and a --parent-profile flag
# cannot raise that (the flag only ever narrows). Every source here is still the worker's OWN
# environment or a file its uid can write: this bounds the spawn path a worker inherits, not a
# worker that scrubs its env or calls the runtime CLI or an agent directly (W4-05 is the ro
# boundary). A coordinator session carries none of them and is unchanged.
if [ -z "$env_parent" ]; then
  for _wv in OPEN_FLEET_DISPATCH_ID ORCA_DISPATCH_ID OPEN_FLEET_WORKER_ID ORCA_WORKER_ID \
             OPEN_FLEET_UNIT_WORKTREE ORCA_UNIT_WORKTREE; do
    [ -n "${!_wv:-}" ] || continue
    env_parent=ro
    echo "SPAWN=NOTE task=${tname} this session carries fleet worker identity (${_wv}) but no parent profile (OPEN_FLEET_PARENT_PROFILE, OPEN_FLEET_SANDBOX_PROFILE, an ORCA_ alias, or a recorded pane): the child is capped at ro, the most restrictive tier, rather than left uncapped (W4-04). A coordinator session must not carry ${_wv}." >&2
    break
  done
fi
eff_parent_profile="$env_parent"
if [ -n "${PARENT_PROFILE:-}" ]; then
  known_parent "$PARENT_PROFILE"
  eff_parent_profile=$(fold_parent "$eff_parent_profile" "$PARENT_PROFILE")
fi
# register_spawn <handle>: record this launch's PROFILE under the pane handle it was given and
# under the worker's pane ROOT process (spawn_identity.py: the process whose initial environment
# names the handle; an uncapped launcher also records its own anchors), THEN drop the reservation
# (that order, so a reader never sees neither). Returns 1 when the handle record cannot be
# written and 2 when the worker's process tree is not verified (spawn_identity.py exits 1:
# nothing found by a scan that was not complete, or no scan at all; or 2: a root it found but
# could not verify): either way the reservation stays, still capping every session nothing else
# identifies. Only a COMPLETE scan that finds no process (SPAWN_ROOT_WAIT_SECS, default 1) means
# no local worker process to record; an environment the scan cannot read is unknown, never "no
# process" (Codex round 4).
register_spawn() {
  if ! registry_key_ok "$1"; then
    echo "SPAWN=WARNING task=${task} the launched pane's handle is not a registry key, so its PROFILE=${PROFILE} cannot be recorded under it (W4-04)" >&2
    return 1
  fi
  if ! { printf '%s\n' "$PROFILE" > "$SPAWN_REGISTRY/.$1.$$" \
      && mv -f -- "$SPAWN_REGISTRY/.$1.$$" "$SPAWN_REGISTRY/$1"; } 2>/dev/null; then
    rm -f -- "$SPAWN_REGISTRY/.$1.$$" 2>/dev/null || true
    echo "SPAWN=WARNING task=${task} could not record PROFILE=${PROFILE} for pane $1 in the spawn registry (${SPAWN_REGISTRY}) (W4-04)" >&2
    return 1
  fi
  local _wait="${SPAWN_ROOT_WAIT_SECS:-1}" _anchor=()
  case "$_wait" in ""|*[!0-9.]*) _wait=1 ;; esac
  # Only a worker that runs HERE, as a process carrying its pane handle, has a process tree to
  # record: Orca's and posix's panes on this host. A remote placement (--environment, --on) or
  # another runtime's worker (an OpenHands conversation, a hosted agent) has none on this host,
  # and its handle record is its record.
  if { [ "$ACTIVE_RUNTIME" != "orca" ] && [ "$ACTIVE_RUNTIME" != "posix" ]; } \
     || [ "$ENV_GIVEN" = "1" ] || [ "$ON_GIVEN" = "1" ]; then
    return 0
  fi
  if [ -z "$eff_parent_profile" ]; then _anchor=(--launcher "$$"); fi  # only an uncapped launcher anchors
  local _rr=0
  python3 -I "$HERE/spawn_identity.py" record-root --registry "$SPAWN_REGISTRY" --handle "$1" \
    --profile "$PROFILE" --wait "$_wait" --since "$$" ${_anchor[@]+"${_anchor[@]}"} >/dev/null 2>&1 || _rr=$?
  # 3: a complete scan found no process carrying the handle — the worker is not a local process
  # (it exited, runs remotely or in another uid's container, or the backend is a dry run), so its
  # handle record is its record. 1 (nothing found, the scan not complete or impossible: without
  # /proc it never is) and 2 (a root found but not verified) keep the reservation.
  if [ "$_rr" != "0" ] && [ "$_rr" != "3" ]; then
    echo "SPAWN=WARNING task=${task} pane $1 is recorded, but its worker's process tree is UNVERIFIED (record-root exit ${_rr}: nothing carrying it was found by a scan that could not read every candidate — an environment that stayed unreadable, or no /proc — or a root it found could not be verified): the launch reservation stays, capping every session nothing else identifies, until it is removed (W4-04)" >&2
    return 2
  fi
  return 0
}
# receipt_handles <receipt> [terminal]: THE one extraction of the pane handles a response names
# (Codex round 4: the verdict parser left at its error-code branch before it read the handle, so
# an error envelope beside a live worker's handle lost both its record and its reservation).
# Every receipt reader below takes its handle from here, and it runs FIRST, before anything judges
# the response: registration, the verdict parser's HANDLE= line, terminal create's pane. It reads
# every place a runtime puts one — result, error, error.data, nested worker/terminal objects,
# effects[] (any terminal effect; role agent is the worker's pane) — whatever the exit code, error
# code or state says. One line per handle, `<role> <status> <value>`: role `agent` (the worker's
# pane, in the parser's order: result.agentTerminalHandle, then the agent terminal effect; for
# terminal create, result.terminal.handle then the bare result.handle older hosts answer) or
# `other`; status `ok` (a registry key), `unprintable` (a control character or a space) or
# `notkey` (anything else, a non-string included); the value always inert. A response that does
# not parse whole (truncated, two documents, a warning line before it) is still searched for
# handle-shaped fields and ends with `PARTIAL`: what it names is registered, but it may name more.
# The last line is `END`; a reader that never sees it treats the response as PARTIAL.
receipt_handles() {
  python3 -I - "$1" "${2:-}" <<'PY'
import json, math, re, sys
KEYS = ("agentTerminalHandle", "terminalHandle", "terminal_handle")
KEY_OK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*\Z")
terminal_mode = sys.argv[2] == "terminal"
named, partial = [], False


class Obj(list):
    """A JSON object as its (key, value) pairs, EVERY occurrence kept (Codex round 5: json.load
    keeps the last of two equal keys, so `"agentTerminalHandle": "term_live",
    "agentTerminalHandle": "term_dead"` hid the live pane)."""


def _pairs(pairs):
    global partial
    if len({k for k, _v in pairs}) != len(pairs):
        partial = True  # a duplicate key: every reader but this one sees a different response
    return Obj(pairs)


def _constant(_c):
    global partial
    partial = True  # NaN / Infinity: not JSON
    return None


def _float(s):
    global partial
    f = float(s)
    if not math.isfinite(f):
        partial = True
    return f


def every(o, key):
    return [v for k, v in o if k == key] if isinstance(o, Obj) else []


def inert(s):
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)


def add(role, v):
    if v is None or v is False or v == "" or v == []:
        return  # names nothing (an empty object is an empty Obj)
    if isinstance(v, str):
        status = "ok" if KEY_OK.match(v) else (
            "unprintable" if any(not c.isprintable() or c.isspace() for c in v) else "notkey")
        named.append((role, status, inert(v)))
    else:
        named.append((role, "notkey", inert(json.dumps(v, sort_keys=True, default=str))))


def effect(e):
    """A terminal (or dispatch_input) effect: the WORKER's pane only with `role: agent`; any other
    role, a missing one or an unknown one is another pane (Codex round 9: a coordinator-role pane
    counted as the worker's)."""
    if not isinstance(e, Obj):
        return
    kinds, roles = every(e, "kind"), every(e, "role")
    if "terminal" not in kinds and "dispatch_input" not in kinds:
        return
    role = "agent" if roles and all(r == "agent" for r in roles) else "other"
    for key in ("id", "handle"):
        for v in every(e, key):
            add(role, v)


def walk(o, depth=0, worker=False):
    """Every handle-shaped field. `agentTerminalHandle` names the worker's pane wherever it sits;
    a generic terminalHandle / terminal_handle / terminal.handle does so only on the result itself
    or inside a `worker` object (`worker`), and anywhere else names another pane."""
    global partial
    if depth > 64:
        partial = True  # nested past what is read: it may name more
        return
    if isinstance(o, Obj):
        for k, v in o:
            if k == "agentTerminalHandle":
                add("agent", v)
            elif k in KEYS:
                add("agent" if worker else "other", v)
            elif k == "terminal" and isinstance(v, Obj):
                for h in every(v, "handle"):
                    add("agent" if worker else "other", h)
            elif k == "effects" and isinstance(v, list) and not isinstance(v, Obj):
                for e in v:
                    effect(e)
            walk(v, depth + 1, k in ("result", "worker") and (worker or k == "worker" or depth == 0))
    elif isinstance(o, list):
        for v in o:
            walk(v, depth + 1)


try:
    raw = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
except OSError:
    raw = ""
parsed = True
try:
    d = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
except ValueError:
    d, parsed, partial = None, False, True
if parsed:
    results = every(d, "result") if isinstance(d, Obj) else []
    rs = [r for r in results if isinstance(r, Obj)] or ([d] if isinstance(d, Obj) else [])
    for r in rs:
        if terminal_mode:  # the order terminal create's pane was always read in
            for term in every(r, "terminal"):
                for h in every(term, "handle"):
                    add("agent", h)
            for h in every(r, "handle"):
                add("agent", h)
        else:  # the order the verdict parser always read the worker's pane in
            for h in every(r, "agentTerminalHandle"):
                add("agent", h)
            for effects in every(r, "effects"):
                for e in effects if isinstance(effects, list) and not isinstance(effects, Obj) else []:
                    if isinstance(e, Obj) and "terminal" in every(e, "kind") and "agent" in every(e, "role"):
                        for h in every(e, "id"):
                            add("agent", h)
    walk(d, 0, not (isinstance(d, Obj) and every(d, "result")))  # a bare result is the result
else:
    # Not one whole document: every handle-shaped field in the text, so a live worker's handle
    # in a truncated or doubled response is still registered.
    s = r'"((?:[^"\\]|\\.)*)"'
    for m in re.finditer(r'"(%s|handle)"\s*:\s*%s' % ("|".join(KEYS), s), raw):
        try:
            add("agent", json.loads('"%s"' % m.group(2)))
        except ValueError:
            add("agent", m.group(2))
    for obj in re.finditer(r"\{[^{}]*\}", raw):
        if re.search(r'"kind"\s*:\s*"terminal"', obj.group(0)):
            for m in re.finditer(r'"(?:id|handle)"\s*:\s*%s' % s, obj.group(0)):
                add("agent", m.group(1))
# One line per handle; a handle the response names as the worker's anywhere is the worker's.
agents = {value for role, _status, value in named if role == "agent"}
seen = set()
for role, status, value in named:
    if value not in seen:
        seen.add(value)
        print(f"{'agent' if value in agents else role} {status} {value}")
if partial:
    print("PARTIAL")
print("END")
PY
}
# read_named <receipt> [terminal]: run receipt_handles once into named_lines (`<role> <status> <value>`),
# agent_handle/agent_status (the worker's pane, if named) and receipt_partial.
named_lines=(); agent_handle=""; agent_status=""; receipt_partial=0
read_named() {
  named_lines=(); agent_handle=""; agent_status=""; receipt_partial=1
  local _role _st _v _end=0 _partial=0
  while read -r _role _st _v; do
    case "$_role" in
      END) _end=1 ;;
      PARTIAL) _partial=1 ;;
      agent|other)
        named_lines+=("$_role $_st $_v")
        if [ "$_role" = "agent" ] && [ -z "$agent_status" ]; then agent_handle="$_v"; agent_status="$_st"; fi ;;
    esac
  done < <(receipt_handles "$1" "${2:-}")
  if [ "$_end" = "1" ] && [ "$_partial" = "0" ]; then receipt_partial=0; fi
}
# register_named: register every handle read_named found (never this session's own). named_count
# counts them across every response this launch read, and named_agent the WORKER's own pane among
# them (role agent): only that one being named lets a reservation go, never an ancillary pane
# alone (Codex round 9); named_unrecorded is 1 when any could not be
# recorded completely (its record not written, its process tree unverified, not a registry key,
# or a response that did not parse whole), and named_record_failed when a handle record itself
# could not be written.
named_count=0; named_agent=0; named_unrecorded=0; named_record_failed=0
register_named() {
  local _line _role _st _h _rs _mine _ph _n=0 _a=0
  for _line in ${named_lines[@]+"${named_lines[@]}"}; do
    _role="${_line%% *}"; _line="${_line#* }"
    _st="${_line%% *}"; _h="${_line#* }"
    _mine=0
    for _ph in ${own_handles[@]+"${own_handles[@]}"}; do
      if [ "$_st" = "ok" ] && [ "$_h" = "$_ph" ]; then _mine=1; fi
    done
    [ "$_mine" = "0" ] || continue
    _n=$((_n + 1))
    if [ "$_role" = "agent" ]; then _a=$((_a + 1)); fi
    if [ "$_st" != "ok" ]; then
      named_unrecorded=1; named_record_failed=1
      echo "SPAWN=WARNING task=${task} the response names a worker pane whose handle is not a registry key ($_h), so it cannot be recorded: the launch reservation stays (W4-04)" >&2
      continue
    fi
    _rs=0; register_spawn "$_h" || _rs=$?
    case "$_rs" in
      0) : ;;
      1) named_unrecorded=1; named_record_failed=1 ;;
      *) named_unrecorded=1 ;;
    esac
  done
  named_count=$((named_count + _n)); named_agent=$((named_agent + _a))
  if [ "$receipt_partial" = "1" ]; then
    named_unrecorded=1
    if [ "$_n" -gt 0 ]; then
      echo "SPAWN=WARNING task=${task} the response did not parse whole, so it may name a worker pane beyond the ${_n} recorded: the launch reservation stays (W4-04)" >&2
    fi
  fi
}
# prelaunch_refusal <receipt>: exit 0 only when the launch call is PROVEN to have started nothing
# (Codex rounds 6 and 7): the WHOLE response is exactly one pre-launch refusal, read against a
# strict schema at every level. The document is `{"id"?, "ok": false?, "error": E}` or
# `{"id"?, "ok": false?, "result": {"error": E}}` (never both); E is `{"code", "message"?,
# "data"?}` with a code a runtime gives BEFORE any launch effect, and its data holds only the
# documented refusal fields (nextSteps, unmetDependencies, retryOf, failureCount, reason) with
# their documented types. Anything else anywhere — a second error, a result beside the error, a
# state, an effect, a handle, an unknown key at any depth, a code outside the list (runtime_error,
# inject_rejected, consumer_fenced, dispatch_inactive, an unknown or untyped one) — leaves the
# outcome unknown, and the reservation stays. The caller also requires that no handle was named
# and that the response parsed whole.
PRELAUNCH_CODES="task_not_found task_not_startable nested_worker_depth_exceeded worktree_not_found selector_not_found invalid_argument"
prelaunch_refusal() {
  pyjson "$1" "$PRELAUNCH_CODES" <<'PY'
CODES = set(sys.argv[2].split())


def strs(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


DATA = {"nextSteps": strs, "unmetDependencies": strs, "retryOf": lambda v: isinstance(v, str),
        "failureCount": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "reason": lambda v: isinstance(v, str)}


def refusal(e):
    if not isinstance(e, dict) or not set(e) <= {"code", "message", "data"}:
        return False
    if not isinstance(e.get("code"), str) or e["code"] not in CODES:
        return False
    if "message" in e and not isinstance(e["message"], str):
        return False
    data = e.get("data", {})
    if data is None:
        return True
    return isinstance(data, dict) and all(k in DATA and DATA[k](v) for k, v in data.items())


try:
    d = strict_load(sys.argv[1])
except Exception:
    raise SystemExit(1)
if not isinstance(d, dict) or not set(d) <= {"id", "ok", "error", "result"}:
    raise SystemExit(1)
if "id" in d and not isinstance(d["id"], str):
    raise SystemExit(1)
if "ok" in d and d["ok"] is not False:
    raise SystemExit(1)  # ok:true (or anything but false) beside a refusal contradicts it
if "error" in d:
    if d.get("result") not in (None, {}):
        raise SystemExit(1)  # a result beside the error, an error inside it included
    err = d["error"]
else:
    r = d.get("result")
    if not isinstance(r, dict) or set(r) != {"error"}:
        raise SystemExit(1)
    err = r["error"]
raise SystemExit(0 if refusal(err) else 1)
PY
}
# release_after_registration: every handle the response named is recorded, so the reservation goes.
release_after_registration() {
  if [ -z "$launch_reservation" ] || rm -f -- "$launch_reservation" 2>/dev/null; then
    launch_reservation=""; keep_reservation=0
  fi
}
# release_reservation (EXIT trap): drop the reservation unless a worker may be live with no record.
# A terminal create that named no pane is released only on a proven pre-launch refusal.
launch_reservation=""; keep_reservation=0
release_reservation() {
  [ -n "$launch_reservation" ] || return 0
  if [ "$keep_reservation" = "1" ] && [ "$named_agent" -gt 0 ] && [ "$named_unrecorded" = "0" ]; then
    keep_reservation=0  # the worker's own pane is named, and every pane named is recorded
  fi
  if [ "$keep_reservation" = "1" ] && [ "$named_count" = "0" ] && [ "$named_unrecorded" = "0" ] \
     && [ "$step" = "create-terminal" ] && [ -s "${tj:-}" ] && prelaunch_refusal "$tj"; then
    keep_reservation=0
  fi
  if [ "$keep_reservation" = "1" ]; then
    echo "SPAWN=NOTE task=${task} launch reservation KEPT: ${launch_reservation} — a worker may be live whose pane was never recorded, so every session without a spawn record of its own stays capped at PROFILE=${PROFILE} until this file is removed. Remove it once worker-list shows no such worker (W4-04)." >&2
  else
    rm -f -- "$launch_reservation" 2>/dev/null || true
  fi
  launch_reservation=""
}
if [ -n "$ACTIVE_RUNTIME" ] && [ "$ACTIVE_RUNTIME" != "orca" ]; then
  WS_ARGS+=(--profile "$PROFILE")
  if [ -n "$eff_parent_profile" ]; then
    WS_ARGS+=(--parent-profile "$eff_parent_profile")
  fi
fi
# Keep a readable worktree/receipt label with a checksum to distinguish squashed titles (#44).
# This is NOT attempt identity: identical titles, retries, and checksum collisions are possible.
# Actual scratch isolation is the atomic directory allocation below, independent of this label.
# Bounded BEFORE any use (W4-12): the label becomes every receipt filename (dispatch-noinject-
# <label>.json is the longest) and the worktree --name, so an unbounded 300-character title failed
# `File name too long` after the task existed. The slug keeps its first 64 bytes (tr leaves it
# ASCII); the checksum still covers the WHOLE title, so titles differing past the cut stay distinct.
# Its leading dashes go too: `--force` became `--name --force-<cksum>`, an option to the runtime,
# and `!!!` squashed to `----<cksum>`; a slug left empty reads `title`.
title_hash=$(printf '%s' "$title" | cksum | cut -d' ' -f1)
title_slug="$(printf '%s' "$title" | tr -c 'A-Za-z0-9._-' '-')"
title_slug="${title_slug:0:64}"
while [ "${title_slug#-}" != "$title_slug" ]; do title_slug="${title_slug#-}"; done
safe_title="${title_slug:-title}-${title_hash}"

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
pin_version=$(python3 -I - "$HERE/../pins.json" <<'PIN'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        print((json.load(fh).get("orca") or {}).get("version") or "")
except Exception:
    print("")
PIN
)
witness_binary=$(python3 -I - "$HERE/../pins.json" <<'PIN'
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
# eff_parent_profile: the most restrictive parent source, folded (and validated) above.
if [ -n "$eff_parent_profile" ]; then
  _pr=$(profile_rank "$eff_parent_profile")
  _cr=$(profile_rank "$PROFILE")
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
  if [ "$ACTIVE_RUNTIME" != "orca" ]; then
    # Off Orca the provider places the worker in `--on <x>` or, absent that, in its own read of
    # OPEN_FLEET_SANDBOX_RECIPE/ORCA_SANDBOX_RECIPE. The doctor below certifies `$recipe`; any
    # OTHER placement source would launch danger somewhere nobody certified (#592).
    if [ -n "${OPEN_FLEET_SANDBOX_RECIPE:-}" ] && [ -n "${ORCA_SANDBOX_RECIPE:-}" ] \
      && [ "$OPEN_FLEET_SANDBOX_RECIPE" != "$ORCA_SANDBOX_RECIPE" ]; then
      echo "SPAWN=REFUSED task=${task} OPEN_FLEET_SANDBOX_RECIPE='${OPEN_FLEET_SANDBOX_RECIPE}' disagrees with ORCA_SANDBOX_RECIPE='${ORCA_SANDBOX_RECIPE}' — one recipe is certified and launched, never two; unset one" >&2
      exit 2
    fi
    if [ "$ON_GIVEN" = "1" ] && [ "$ON_ENV" != "$recipe" ]; then
      echo "SPAWN=REFUSED task=${task} --on '${ON_ENV}' differs from the sandbox recipe '${recipe}' this script certifies — danger launches only in the recipe the doctor cleared" >&2
      exit 2
    fi
  fi
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
  # stdout is the receipt the verdict reader parses; stderr is kept beside it for forensics
  # (dispatch-lifecycle.md: keepalives go to stderr, pipe stdout only into parsers). Merged, one
  # warning line made every receipt unparseable (2026-10-26 review).
  "$ORCA_BIN" vm recipe doctor "$recipe" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$doctor_out" 2> "$doctor_out.stderr" || doctor_rc=$?
  if [ "$doctor_rc" -ne 0 ] && cat "$doctor_out" "$doctor_out.stderr" | grep -qiE "unknown (option|flag|argument)|unrecognized|invalid option"; then
    doctor_rc=0
    "$ORCA_BIN" vm recipe doctor "$recipe" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} > "$doctor_out" 2> "$doctor_out.stderr" || doctor_rc=$?
  fi
  if [ "$doctor_rc" -ne 0 ]; then
    echo "SPAWN=REFUSED task=${task} \`${ORCA_BIN} vm recipe doctor ${recipe}\` exited ${doctor_rc} — the sandbox did not come up clean: $(cat "$doctor_out" "$doctor_out.stderr" | head -c 300 | inert_text)" >&2
    rm -f "$doctor_out"
    exit 2
  fi
  if ! python3 -I "$HERE/sandbox_doctor.py" "$doctor_out" "$recipe" 2>/dev/null; then
    echo "SPAWN=REFUSED task=${task} recipe doctor for '${recipe}' is not clear — sandbox-policy.md: clear means no fail AND no warn (ok:true alone proves nothing): $(python3 -I "$HERE/sandbox_doctor.py" "$doctor_out" "$recipe" 2>&1 >/dev/null | head -c 200 | inert_text)" >&2
    rm -f "$doctor_out"
    exit 2
  fi
  # A non-Orca runtime answers the same `vm recipe doctor` through orca_cli.py; providers
  # without a real probe fail closed (unsupported_operation → nonzero above). A PORTABLE
  # backend's transcript can additionally prove prelaunch placement — evidence Orca's
  # recipe doctor cannot give — and, isolation-checked by sandbox_doctor.py, that is what
  # lets danger launch there (#585). A command override bypasses the provider's placement,
  # so it never qualifies.
  placement_bound=0
  case "$agent" in
    claude) _danger_override="${CLAUDE_CMD:-${WORKER_CMD:-}}" ;;
    codex)  _danger_override="${CODEX_CMD:-${WORKER_CMD:-}}" ;;
    *)      _danger_override="${WORKER_CMD:-}" ;;
  esac
  if [ "$ACTIVE_RUNTIME" != "orca" ] && [ -z "$_danger_override" ] \
    && python3 -I "$HERE/sandbox_doctor.py" --require-placement "$doctor_out" "$recipe" 2>/dev/null; then
    placement_bound=1
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
  if [ "$placement_bound" = "1" ]; then
    # Bind the launch to EXACTLY the certified recipe: --on wins over the provider's env read.
    if [ "$ON_GIVEN" != "1" ]; then WS_ARGS+=(--on "$recipe"); fi
    export OPEN_FLEET_SANDBOX_RECIPE="$recipe" ORCA_SANDBOX_RECIPE="$recipe"
    echo "SPAWN=NOTE task=${task} runtime '${ACTIVE_RUNTIME}' doctor binds prelaunch placement for recipe='${recipe}' with isolation proven (sandbox_doctor.py --require-placement) — danger proceeds through its worker-start --on '${recipe}' (#585)" >&2
  else
    # Doctor proves recipe health, not this selector's execution placement (R1). The documented
    # probe can clean up its instance; worker-start --on names a saved server, not that instance.
    # Neither supported launch lane binds the validated disposable environment BEFORE launch.
    # Fail closed here, before task mutation or either launch, including command overrides.
    # A receipt inspected after launch is too late; do not invent placement fields or trust a path.
    echo "SPAWN=REFUSED task=${task} PROFILE=danger has no supported authoritative placement binding for worktree='${sel}' to the validated disposable sandbox. A clear doctor is insufficient. Implement and validate prelaunch placement binding before enabling danger; use PROFILE=ro or PROFILE=rw only for work authorized for those profiles." >&2
    exit 2
  fi
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
  # claude ro is plan mode PLUS base.py's CLI floor, the disallowed set `=`-joined as base.py's label
  # spells it: the coordinator's in-pane plan approval exits plan mode, and the set still holds
  # after it (#596). This is the live-witnessed Orca route; the 2026-10-26 #680 witness ran it with the set.
  claude:ro)                 cmd_default="claude --permission-mode plan --disallowedTools=Edit,Write,MultiEdit,NotebookEdit" ;;
  claude:rw|claude:danger)   cmd_default="claude --dangerously-skip-permissions" ;;
  codex:ro)                  cmd_default="codex --sandbox read-only $_cx_effort" ;;
  codex:rw|codex:danger)     cmd_default="codex --dangerously-bypass-approvals-and-sandbox $_cx_effort" ;;
  gemini:ro)                 cmd_default="gemini --approval-mode plan" ;;
  gemini:rw|gemini:danger)   cmd_default="gemini --yolo" ;;
  cursor:rw|cursor:danger)   cmd_default="cursor --yolo" ;;
  antigravity:rw|antigravity:danger) cmd_default="agy --dangerously-skip-permissions" ;;
  grok:rw|grok:danger)       cmd_default="grok --permission-mode bypassPermissions" ;;
  droid:rw|droid:danger)     cmd_default="droid --auto high" ;;
  # jcode/hermes ro carry base.py's source-audited ro restriction (_build_harness_command;
  # docs/runtimes.md harness table) as TUI lines that dispatch --inject can reach (#596): jcode's
  # --tools allowlist + --disabled-tools set (`--profile minimal` keeps bash/write/edit/replace),
  # hermes' /dev/null write root + a toolset with no terminal (its `file` toolset bundles writes).
  # crush has NO ro row: no flag makes it read-only — base.py's ro is `<data-dir>/crush.json`
  # disabled_tools, which only posix's install_worktree_hooks writes, and `crush run` auto-approves
  # every tool — so crush ro fails closed to WORKER_CMD on Orca.
  jcode:ro)                  cmd_default="jcode --no-session --no-update --tools read,agentgrep,ls,session_search,conversation_search,memory,web_search --disabled-tools bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp" ;;
  jcode:rw|jcode:danger)     cmd_default="jcode --no-session" ;;
  goose:ro)                  cmd_default="GOOSE_MODE=chat goose run --no-session" ;;
  goose:rw|goose:danger)     cmd_default="GOOSE_MODE=auto goose run --no-session" ;;
  hermes:ro)                 cmd_default="HERMES_WRITE_SAFE_ROOT=/dev/null hermes chat --toolsets file,web,session_search" ;;
  hermes:rw|hermes:danger)   cmd_default="hermes chat --yolo" ;;
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
# Lane. An override always takes the custom-argv lane (terminal create + dispatch --inject). On
# Orca so does ro: worker-start there launches the HOST's agentDefaultArgs (the YOLO map). Off
# Orca the provider builds the launch itself from `--profile` — base.py's line WITH the task spec
# as its prompt, in the resolved worktree, with a dispatch record — so ro rides worker-start too.
# base.py's ro lines are one-shot and prompt-bound; a TUI awaiting an inject they are not (#592).
custom_lane=0
if [ -n "$override" ] || { [ "$PROFILE" = "ro" ] && [ "$ACTIVE_RUNTIME" = "orca" ]; }; then
  custom_lane=1
fi

# A non-Orca runtime launches what runtime/providers/base.py builds — ONE launch table. This
# script's own rows above were weaker for exactly the harnesses whose read-only mode is
# subtle (crush auto-approves every `run`; hermes bundles writes into `file`; jcode's minimal
# profile keeps bash/edit), so ro here must be base.py's `shell` line verbatim (#580). An
# (agent, profile) base.py refuses leaves cmd_default empty and fails closed to WORKER_CMD.
# base_launch <worktree>: line 1 the `shell` launch, line 2 its profile_flag; empty on refusal.
# openhands has no argv: its line names the agent-server conversation the provider starts (#596).
base_launch() {
  python3 -I - "$HERE/.." "$agent" "$PROFILE" "$1" "$effort" <<'PY' || true
import sys
sys.path.insert(0, sys.argv[1])
from providers.base import ProviderError, build_harness_command
try:
    if sys.argv[2] == "openhands":
        from providers.openhands import launch_line
        launch = launch_line(sys.argv[3])
    else:
        launch = build_harness_command(sys.argv[2], sys.argv[3], sys.argv[4], None, effort=sys.argv[5])
    print(launch["shell"])
    print(launch["profile_flag"])
except ProviderError as err:
    msg = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(err.message))
    print(f"spawn_worker: base.py has no {sys.argv[3]} launch for {sys.argv[2]}: {msg}", file=sys.stderr)
PY
}
base_profile_flag=""
if [ "$ACTIVE_RUNTIME" != "orca" ]; then
  # A selector is never a path: `codex exec -C new-child` and `cd current && …` ran nowhere.
  # Resolve it the way the runtime does — path:/…::<path> name it; current/active are the repo
  # top-level; new-* is CREATED through the runtime's own `worktree create` (only for the ro
  # worker-start lane, which then names the created path; rw/danger let worker-start create it).
  _base="${OPEN_FLEET_REPO_ROOT:-${OPEN_FLEET_CLI_CWD:-${ORCA_CLI_CWD:-$(pwd)}}}"
  _repo_top=$(git -C "$_base" rev-parse --show-toplevel 2>/dev/null || (cd "$_base" && pwd -P))
  case "$sel" in
    path:*) _launch_wt="${sel#path:}" ;;
    *::*) _launch_wt="${sel##*::}" ;;
    current|active) _launch_wt="$_repo_top" ;;
    *) _launch_wt="$sel" ;;
  esac
  _bl=$(base_launch "$_launch_wt")
  # Only a runtime with a standalone `worktree create` can pre-create one; overstory, gastown,
  # t3code and the daemon adapters create the worktree inside worker-start and inherit the
  # base class's unsupported method, so they keep the original new-* selector (#592 review).
  _standalone_wc=$(python3 -I - "$HERE/../.." "$ACTIVE_RUNTIME" <<'PY' || echo 0
import importlib, sys
sys.path.insert(0, sys.argv[1])
prov = importlib.import_module("runtime.providers")
mod_name, cls_name = prov._PROVIDER_MODULES[sys.argv[2]]
cls = getattr(importlib.import_module(mod_name, package="runtime.providers"), cls_name)
print(1 if cls.worktree_create is not prov.RuntimeProvider.worktree_create else 0)
PY
)
  case "$sel" in
    new-*)
      if [ -n "$_bl" ] && [ "$PROFILE" = "ro" ] && [ "$custom_lane" = "0" ] && [ "$_standalone_wc" = "1" ]; then
        step=worktree-create
        _wc=$(mktemp)
        orca_json "$_wc" worktree create --name "$safe_title" --repo "$_repo_top" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"}
        _launch_wt=$(pyjson "$_wc" <<'PY'
import json, sys
d = strict_load(sys.argv[1])
r = d.get("result", d) if isinstance(d, dict) else {}
wt = (r.get("worktree") or {}) if isinstance(r, dict) else {}
p = wt.get("path") if isinstance(wt, dict) else None
if not p or not isinstance(p, str):
    print("worktree create returned no path", file=sys.stderr)
    raise SystemExit(1)
print(p)
PY
)
        rm -f "$_wc"
        sel="path:${_launch_wt}"
        echo "SPAWN=NOTE task=${tname} worktree ${_launch_wt} created for the ${ACTIVE_RUNTIME} ro launch" >&2
        _bl=$(base_launch "$_launch_wt")
      fi ;;
  esac
  cmd_default=$(printf '%s\n' "$_bl" | sed -n '1p')
  base_profile_flag=$(printf '%s\n' "$_bl" | sed -n '2p')
fi

# W4-04 re-attack: an override replaces the PROFILE's command and its opt-in is the caller's own
# env, so a capped worker (`PROFILE=ro WORKER_CMD='claude --dangerously-skip-permissions'`) could
# name any command and still pass the label check. Overrides are a coordinator-only facility.
if [ -n "$override" ] && [ -n "$eff_parent_profile" ]; then
  echo "SPAWN=REFUSED task=${task} a launch override (WORKER_CMD / CLAUDE_CMD / CODEX_CMD) is a coordinator-only facility, and this session is capped at parent profile '${eff_parent_profile}': the override would replace the PROFILE's command with any command at all (W4-04)" >&2
  exit 2
fi
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

# Contract hook: print the resolved launch and stop before any orchestration side effect,
# so a test can hold this script's launch table to base.py's (#580).
if [ -n "${SW_PRINT_LAUNCH:-}" ]; then
  printf 'LAUNCH=%s\n' "$cmd"
  exit 0
fi

# worker-start-only flags on the custom-argv lane (overrides + PROFILE=ro on Orca) would be
# silently dropped — no worker-start runs there. Refuse rather than mislead. (--run/--from/--spec
# stay: dispatch --inject and task-create accept them.)
if [ "$custom_lane" = "1" ]; then
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
  # Orca's `terminal create` takes an existing worktree (path:, id:, name:, branch:, current);
  # new-child/new-top-level create one only through worker-start. Refuse before task-create
  # rather than fail at terminal create with the task already made (#596 Orca re-witness).
  if [ "$ACTIVE_RUNTIME" = "orca" ]; then
    case "$sel" in
      new-child|new-top-level)
        echo "SPAWN=REFUSED task=${tname} --worktree '${sel}' creates a worktree only through worker-start, and this spawn takes the custom-argv lane (override or PROFILE=ro), whose terminal create needs an existing worktree — pass path:<abs-path>, id:<repoId>::<path> or current" >&2
        exit 2 ;;
    esac
  fi
fi

# Deny-hook arming (#562): the rw safety story names the PreToolUse guard, but
# nothing checked it was actually wired into the worker's settings — the claim
# was doctrinal. When the operator names the wired settings file, verify
# fail-closed: it must register deny-hook.sh AND the hook must answer a deny
# probe. The gate now runs for EVERY profile including ro, so a wired guard is
# verified rather than skipped (W4-06: ro skipped the block entirely, so a ro
# worker -- which can still write through Bash, W4-05 -- never even saw the
# warning). Where the settings var is UNSET, OPEN_FLEET_REQUIRE_DENY_HOOK=1 (legacy
# ORCA_REQUIRE_DENY_HOOK) refuses first, on every runtime, before any deferral or
# opt-out (W4-06). Otherwise the behaviour splits on the runtime. The posix and
# openhands providers install the registration and verify it before the agent
# starts (posix.verify_installed_guard; openhands.verify_conversation_guard before
# the conversation's /run): a new-child spawn has no worktree or settings file at
# this pre-launch gate, so the gate cannot check one and defers to that enforcement
# -- ordinary dispatch needs no opt-out. Any other non-Orca provider installs but
# does not verify, so the gate proceeds with an UNVERIFIED warning. ON ORCA
# worker-start is Orca's own and wires no open-fleet guard, so an unset var
# REFUSES, every profile (ro too: a ro claude/gemini worker still writes through
# Bash, W4-05). OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK=1 (legacy
# ORCA_ALLOW_UNVERIFIED_DENY_HOOK) is the Orca-lane opt-out to a loud warning,
# which REQUIRE overrides so an inherited value cannot reopen the warning path.
step=deny-hook-arming
DENY_HOOK_SETTINGS="${OPEN_FLEET_DENY_HOOK_SETTINGS:-${ORCA_DENY_HOOK_SETTINGS:-}}"
REQUIRE_DENY_HOOK="${OPEN_FLEET_REQUIRE_DENY_HOOK:-${ORCA_REQUIRE_DENY_HOOK:-0}}"
ALLOW_UNVERIFIED_HOOK="${OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK:-${ORCA_ALLOW_UNVERIFIED_DENY_HOOK:-0}}"
if true; then
  if [ -n "$DENY_HOOK_SETTINGS" ]; then
    # The hook verifies its own registration: parses the settings, then runs
    # the REGISTERED command (not this repo's copy) under its configured env
    # against deny/allow probes. A mention of the filename is not arming.
    # The gate verifies the HARNESS this spawn launches and the worktree it launches into
    # (2026-10-26 review): a claude registration bounding another tree armed nothing for a codex
    # worker here, and the gate used to be told neither. Harness names the hook does not know
    # (gemini, antigravity, …) stay inferred from the settings path, as before.
    _vs_args=()
    case "$agent" in
      claude|codex|openhands|goose|crush|hermes|opencode|omp|pi|jcode) _vs_args+=(--harness "$agent") ;;
    esac
    # The tree this spawn launches into, for EVERY selector that names an existing one (W4-03,
    # 2026-10-27 audit): only path: used to reach the gate, so an id:<repoId>::<path> spawn (the
    # form the custom-lane refusal recommends) and every current/active/name:/branch: spawn was
    # certified against a registration bounding any tree at all. path: and <repoId>::<path>
    # carry the path; a lookup form is resolved by the runtime's own `worktree show` (off Orca,
    # current/active as base_launch resolved them above). Only new-child/new-top-level name no
    # tree yet. A tree the runtime does not resolve refuses: nothing shows the registration
    # bounds it.
    _vs_wt=""
    case "$sel" in
      new-child|new-top-level) : ;;
      path:*) _vs_wt="${sel#path:}" ;;
      *::*) _vs_wt="${sel##*::}" ;;
      *)
        if [ "$ACTIVE_RUNTIME" != "orca" ] && [ -n "${_launch_wt:-}" ] && [ "$_launch_wt" != "$sel" ]; then
          _vs_wt=$_launch_wt
        else
          _vs_show=$(mktemp)
          if orca_json "$_vs_show" worktree show --worktree "$sel" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} 2>/dev/null; then
            _vs_wt=$(python3 -I - "$_vs_show" <<'PY' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(1)
r = d.get("result", d) if isinstance(d, dict) else {}
wt = r.get("worktree") if isinstance(r, dict) else None
wt = wt if isinstance(wt, dict) else {}
p = wt.get("path")
if not isinstance(p, str) or not p.startswith("/"):
    wid = wt.get("id")
    p = wid.split("::", 1)[1] if isinstance(wid, str) and "::" in wid else ""
if not p.startswith("/"):
    raise SystemExit(1)
print(p)
PY
)
          fi
          rm -f "$_vs_show"
          if [ -z "$_vs_wt" ]; then
            echo "SPAWN=REFUSED task=${task} deny-hook not armed: the runtime did not resolve worktree '${sel}' to a path, so the registration cannot be checked against the tree this spawn launches into (W4-03) — pass path:<abs-path> or id:<repoId>::<path>" >&2
            exit 2
          fi
        fi ;;
    esac
    [ -z "$_vs_wt" ] || _vs_args+=(--boundary "$_vs_wt")
    if ! _arming=$(sh "$HERE/deny-hook.sh" --verify-settings "$DENY_HOOK_SETTINGS" ${_vs_args[@]+"${_vs_args[@]}"} 2>&1); then
      echo "SPAWN=REFUSED task=${task} deny-hook not armed: ${_arming} — wire it (deny-hook.sh --settings <worktree>) or unset ORCA_DENY_HOOK_SETTINGS to proceed UNVERIFIED" >&2
      exit 2
    fi
  elif [ "$REQUIRE_DENY_HOOK" != "0" ] && [ -n "$REQUIRE_DENY_HOOK" ]; then
    # Checked BEFORE any deferral (W4-06, Codex g1 r3 P1): the hardened lock means this gate
    # itself verifies a named registration, on every runtime. It used to sit after the off-Orca
    # deferral, so REQUIRE could not stop a launch the provider never verified.
    echo "SPAWN=REFUSED task=${task} deny-hook arming UNVERIFIED for PROFILE=${PROFILE} on runtime ${ACTIVE_RUNTIME}: OPEN_FLEET_REQUIRE_DENY_HOOK is set and ORCA_DENY_HOOK_SETTINGS is unset, so the PreToolUse guard this tier's safety story names is not verified here: no opt-out is honoured, and no provider deferral either (W4-06). Wire it (deny-hook.sh --settings <worktree>) and name it with ORCA_DENY_HOOK_SETTINGS." >&2
    exit 2
  elif [ "$ACTIVE_RUNTIME" = "posix" ] || [ "$ACTIVE_RUNTIME" = "openhands" ]; then
    # These providers install the deny-hook registration and verify it before the agent starts
    # (W4-06): posix inside worker-start (posix.verify_installed_guard), openhands on the
    # hook_config the agent-server runs, before the conversation's /run (verify_conversation_guard).
    # A new-child spawn has no worktree and no settings file at this pre-launch gate, so the gate
    # cannot and need not check one; it defers to that enforcement rather than demand an opt-out
    # for ordinary dispatch.
    echo "spawn_worker: NOTE deny-hook arming is verified by the ${ACTIVE_RUNTIME} provider inside worker-start for PROFILE=${PROFILE} (ORCA_DENY_HOOK_SETTINGS unset); the agent does not start unless its installed registration is armed (W4-06)" >&2
  elif [ "$ACTIVE_RUNTIME" != "orca" ]; then
    # Every other non-Orca provider installs the registration but does not re-verify it before
    # the agent starts, so the deferral is named for what it is; OPEN_FLEET_REQUIRE_DENY_HOOK=1
    # (above) refuses it.
    echo "spawn_worker: WARNING deny-hook arming UNVERIFIED for PROFILE=${PROFILE} on runtime ${ACTIVE_RUNTIME}: its provider installs the guard in worker-start but does not verify it before the agent starts (ORCA_DENY_HOOK_SETTINGS unset); name the registration in ORCA_DENY_HOOK_SETTINGS, or set OPEN_FLEET_REQUIRE_DENY_HOOK=1 to refuse (W4-06)" >&2
  elif [ "$ALLOW_UNVERIFIED_HOOK" != "0" ] && [ -n "$ALLOW_UNVERIFIED_HOOK" ]; then
    if [ "$PROFILE" = "ro" ]; then
      echo "spawn_worker: WARNING deny-hook arming UNVERIFIED for PROFILE=ro (ORCA_DENY_HOOK_SETTINGS unset, OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK set) — ro relies on the tool filter, which a shell tier writes past; wire deny-hook.sh --settings <worktree> --readonly for the in-hook write floor (W4-05)" >&2
    else
      echo "spawn_worker: WARNING deny-hook arming UNVERIFIED for PROFILE=${PROFILE} (ORCA_DENY_HOOK_SETTINGS unset, OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK set) — worktree + review are the only safety layer this gate can vouch for (W4-06)" >&2
    fi
  else
    echo "SPAWN=REFUSED task=${task} deny-hook arming UNVERIFIED for PROFILE=${PROFILE}: the Orca runtime's worker-start wires no open-fleet guard and ORCA_DENY_HOOK_SETTINGS is unset, so the PreToolUse guard this tier's safety story names is not verified (W4-06). Wire it (deny-hook.sh --settings <worktree>, --readonly for ro) and name it with ORCA_DENY_HOOK_SETTINGS, or set OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK=1 to proceed on an unverified guard." >&2
    exit 2
  fi
fi

# --- reserve this launch in the spawn registry (W4-04) -----------------------
# Before any task mutation or launch call, so a registry that cannot be written refuses the spawn
# instead of starting a worker whose own spawns nothing caps (Codex round 2: HOME unset or
# unwritable only warned). The reservation stands for the pane until register_spawn replaces it
# with the pane's record; the EXIT trap drops it on every path where no worker was started.
step=reserve-launch
_rtmp=""
if [ -z "${HOME:-}" ] || [ -z "$SPAWN_REGISTRY" ] || ! { mkdir -p -m 700 -- "$SPAWN_REGISTRY" && mkdir -p -m 700 -- "$SPAWN_PENDING" \
    && _rtmp=$(mktemp "$SPAWN_PENDING/.r.XXXXXXXX") \
    && printf '%s %s %s %s\n' "$PROFILE" "${own_handles[0]:--}" "${self_key%%.*}" "${self_key#*.}" > "$_rtmp" \
    && mv -f -- "$_rtmp" "$SPAWN_PENDING/r.$$.${_rtmp##*.}"; } 2>/dev/null; then
  if [ -n "$_rtmp" ]; then rm -f -- "$_rtmp" 2>/dev/null || true; fi
  echo "SPAWN=REFUSED task=${task} cannot reserve this launch in the spawn registry ($([ -n "${HOME:-}" ] && printf '%s' "$SPAWN_REGISTRY" || printf 'HOME is unset')): a worker launched without a record would spawn uncapped, so nothing is launched (W4-04)" >&2
  exit 2
fi
launch_reservation="$SPAWN_PENDING/r.$$.${_rtmp##*.}"
trap '_rc=$?; release_reservation; exit "$_rc"' EXIT
trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM  # through the EXIT trap above

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
  task=$(pyjson "$tc" <<'PY'
import json, sys
try:
    d = strict_load(sys.argv[1])
except Exception:
    d = {}
r = d.get("result") if isinstance(d, dict) else None
tid = (r.get("task") or {}).get("id") if isinstance(r, dict) else None
if not tid or not isinstance(tid, str):
    print("task-create returned no task id", file=sys.stderr)
    raise SystemExit(1)
if not all(c.isprintable() and not c.isspace() for c in tid):
    print("task-create returned a task id that is not one printable token", file=sys.stderr)
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
tl_out=$(pyjson "$tl" "$task" <<'PY'
import json, sys


def _f(v):
    """A receipt field, inert and on one line (W4-11): anything unprintable escaped."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(v))


def emit(status, unmet):
    """unmet on line 1, status on line 2 — the shell reads lines, never words."""
    print(unmet)
    print(_f(status))
    raise SystemExit(0)


path, tid = sys.argv[1], sys.argv[2]
d = strict_load(path)
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
        deps = strict_loads(deps)  # "" and garbage both fail here -> refusal below
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
#                                           ro NEVER takes worker-start ON ORCA. (Host-dependent: a
#                                           manual-mode host has `''` — probe owed, pin-it.)
#   PROFILE=ro off Orca, no override      → supervised worker-start --profile ro: the provider
#                                           builds base.py's ro line itself, with the task prompt
#   PROFILE=rw|danger, no override        → supervised worker-start lane
step=spawn
ws="$SP/ws-$safe_title.json"
if [ "$custom_lane" = "0" ]; then
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
  keep_reservation=1  # from here a worker may be live: its reservation stays until a verdict says otherwise
  # stdout only into the receipt: a keepalive or warning line on stderr turned a READY receipt
  # into UNPARSEABLE_RECEIPT / OUTCOME_UNKNOWN and lost a live worker's handle (2026-10-26 review).
  # stderr is kept beside it ($ws.stderr) for forensics.
  "$ORCA_BIN" orchestration worker-start --task "$task" --worktree "$sel" ${name_args[@]+"${name_args[@]}"} --agent "$agent" ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} ${WS_ARGS[@]+"${WS_ARGS[@]}"} --json > "$ws" 2> "$ws.stderr" || ws_rc=$?
  # Every handle the response names may be a live worker, whatever its exit code, error code or
  # state says, so it is read once and registered BEFORE the response is judged (Codex rounds 3
  # and 4); the verdict parser prints the same handle rather than reading its own.
  step=register-spawn
  read_named "$ws"
  register_named
  ws_handle="$agent_handle"
  ws_partial="$receipt_partial"

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
  # ro off Orca: the provider launched base.py's ro line, so ITS flag is the one to find. The
  # openhands agent's toolset token comes from its provider for every profile (#596).
  if [ "$PROFILE" = "ro" ] || [ "$agent" = "openhands" ]; then profile_flag="$base_profile_flag"; fi

  step=read-start-receipt
  # Line 1 is the machine verdict; the remaining stdout lines are the caller-facing receipt
  # fields. nextSteps / nextCommands go to stderr verbatim — they are the runtime's own
  # recovery text, not ours to paraphrase.
  ws_out=$(pyjson "$ws" "$profile_flag" "$ws_handle" <<'PY'
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


def _f(v):
    """A receipt field, inert and on one line (W4-11): anything unprintable escaped."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(v))


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
    d = strict_load(sys.argv[1])
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
code = _f(err.get("code") or "")
data = err.get("data") if isinstance(err.get("data"), dict) else {}
w = r.get("worker")
state = r.get("state") or (w.get("state") if isinstance(w, dict) else None)
did = r.get("dispatchId") or r.get("dispatch_id") or ""
# The worker's pane handle, read ONCE by receipt_handles before this parser runs (the agent
# terminal effect, agentTerminalHandle, or wherever else the response names one, error envelope
# included), so no branch below can lose it: every verdict prints it when the response names one.
h = sys.argv[3] if len(sys.argv) > 3 else ""
# Older hosts may omit `data` entirely — treat every field as optional.
for s in data.get("nextSteps") or []:
    print(f"nextStep: {_f(s)}", file=sys.stderr)
if code in POLICY_CODES or code:
    print(f"VERDICT={'refused' if code in POLICY_CODES else 'failed'} CODE={code}")
    if h:  # an error envelope beside a handle: a worker may be live there
        print(f"HANDLE={_f(h)} READY={_f(state or 'error')}")
    raise SystemExit(0)

if state == "outcome_unknown":
    # NOT a failure: the start neither proved nor disproved the worker. The receipt names the
    # exact inspection commands; a respawn here is the dual-writer class.
    for c in r.get("nextCommands") or []:
        print(f"nextCommand: {_f(c)}", file=sys.stderr)
    print(f"VERDICT=unknown STATE={_f(state)}")
    print(f"HANDLE={_f(h)} READY={_f(state)}")
    print(f"DISPATCH={_f(did)}")
    raise SystemExit(0)
if state is not None and state != "ready":
    print(f"VERDICT=failed STATE={_f(state)}")
    if h:  # a receipt naming a handle may have a live worker behind it: the shell registers it
        print(f"HANDLE={_f(h)} READY={_f(state)}")
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
    print(f"HANDLE={_f(h)} READY=absent")
    print(f"DISPATCH={_f(did)}")
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
        why = "LAUNCH_FLAG_MISSING=" + _f(" ".join(want))
    else:
        why = ""
    if why:
        print("VERDICT=unusable " + why)
        print(f"HANDLE={_f(h)} READY={_f(state)}")
        print(f"DISPATCH={_f(did)}")
        if eff is not None:
            print("LAUNCH_EFFECTIVE=" + _f(eff if isinstance(eff, str)
                                           else json.dumps(eff, sort_keys=True)))
        raise SystemExit(0)

print(f"VERDICT=ready STATE={_f(state)}")
print(f"HANDLE={_f(h)} READY={_f(state)}")
print(f"DISPATCH={_f(did)}")
if eff is not None:
    print("LAUNCH_EFFECTIVE=" + _f(eff if isinstance(eff, str) else json.dumps(eff, sort_keys=True)))
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
      "$ORCA_BIN" orchestration request-show --request "$RETRY_REQUEST" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$rq" 2> "$rq.stderr" || rq_rc=$?
      # A landed mutation's record may name the worker's pane that the start response did not:
      # registered like any other response that names one.
      step=register-spawn
      read_named "$rq"
      register_named
      step=triage-request
      rq_state=$(pyjson "$rq" <<'PY'
import json, sys
try:
    d = strict_load(sys.argv[1])
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

  # W4-04: any response that NAMES a handle may have a live worker behind it, whatever the exit
  # code, error code or verdict (Codex round 3: a ready receipt from a call that exited nonzero;
  # round 4: an error envelope beside a ready result). Each was registered above, before the
  # verdict. With every named worker recorded completely the reservation goes; with any record
  # incomplete it stays, capping every session nothing else identifies. With none named, only a
  # refusal PROVEN to precede any launch effect lets it go (prelaunch_refusal, Codex round 6): any
  # other failure, a policy refusal that can follow a pane's creation included, is unknown, and
  # unknown means a worker may be live.
  if [ "$named_count" -gt 0 ]; then
    if [ "$named_agent" -gt 0 ] && [ "$named_unrecorded" = "0" ]; then
      release_after_registration
    elif [ "$named_agent" = "0" ]; then
      echo "SPAWN=WARNING task=${task} the response names only panes other than the worker's own (no agent-role handle): the worker's pane is unnamed, so its launch reservation stays (W4-04)" >&2
    else
      echo "SPAWN=WARNING task=${task} a worker the response names may be live without a complete spawn record; its launch reservation stays instead (W4-04)" >&2
    fi
  elif [ "$ws_partial" = "0" ] && prelaunch_refusal "$ws"; then
    keep_reservation=0
  fi

  step=verify-ready
  # A refused or failed verdict whose response still names a pane: print it, and say a worker may
  # be live there, so nothing respawns beside it uninspected.
  named_pane_note() {
    if [ -n "$ws_handle" ]; then
      printf '%s\n' "$payload" | grep '^HANDLE=' || true
      echo "SPAWN=WARNING task=${task} the response names pane ${ws_handle} beside its error: a worker may be live there (its PROFILE=${PROFILE} is registered, or the launch reservation stays). INSPECT it (worker-list, worker-show) before any retry (W4-04)" >&2
    fi
  }
  case "$verdict" in
    ready)
      printf '%s\n' "$payload"
      ;;
    refused)
      named_pane_note
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
      named_pane_note
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
  keep_reservation=1  # the command may be running before terminal create returns its handle
  tc_rc=0
  "$ORCA_BIN" terminal create --worktree "$sel" --title "$title" --command "$cmd" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$tj" || tc_rc=$?
  # Any pane the response names may be live, whatever it says next (Codex round 4): it is read once
  # (receipt_handles, the one extraction) and registered FIRST; then a nonzero exit or an error
  # envelope fails as orca_json did, naming the pane it leaves behind.
  step=register-spawn
  read_named "$tj" terminal
  register_named
  h="$agent_handle"
  step=create-terminal
  tc_err=0
  if [ "$tc_rc" != "0" ]; then tc_err="$tc_rc"; elif ! envelope_check "$tj"; then tc_err=1; fi
  if [ "$tc_err" != "0" ]; then
    if [ -n "$h" ]; then
      echo "SPAWN=WARNING task=${task} terminal create failed but names pane ${h}: it may be live (its PROFILE=${PROFILE} is registered, or the launch reservation stays); close it (${ORCA_BIN} terminal close --terminal ${h}) (W4-04)" >&2
    fi
    (exit "$tc_err")
  fi
  if [ -z "$h" ] || [ "$h" = "None" ]; then
    named_unrecorded=1  # a pane may be live that nothing names: its reservation stays
    echo "terminal create returned no handle" >&2
    (exit 1)
  fi
  if [ "$agent_status" = "unprintable" ]; then
    echo "terminal create returned a handle that is not one printable token (${h})" >&2
    (exit 1)
  fi
  # The record replaces the reservation before anything is injected. If it cannot be written the
  # pane gets no task, and its reservation stays (the EXIT trap says so), capping it regardless.
  step=register-spawn
  if [ "$named_unrecorded" = "0" ] && [ "$named_agent" -gt 0 ]; then release_after_registration; fi
  if [ "$named_record_failed" = "1" ] || [ "$named_agent" = "0" ]; then
    echo "SPAWN=FAILED task=${task} step=${step} rc=1 — pane ${h} is LIVE but its PROFILE=${PROFILE} could not be recorded, so nothing was injected into it: close it (${ORCA_BIN} terminal close --terminal ${h}) (W4-04)" >&2
    exit 1
  fi

  step=wait-tui-idle
  # READ the result. A timed-out wait prints a normal result carrying `wait.satisfied:false` AND
  # sets exit 1; relying on the exit code alone (v4) was failing closed by accident. An absent
  # field is an older host, not a false — do not invent a verdict from absence.
  tw="$SP/tw-$safe_title.json"
  wait_rc=0
  "$ORCA_BIN" terminal wait --terminal "$h" --for tui-idle --timeout-ms 90000 ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$tw" 2> "$tw.stderr" || wait_rc=$?
  satisfied=$(pyjson "$tw" <<'PY'
import json, sys
try:
    d = strict_load(sys.argv[1])
except Exception:
    # An unreadable wait receipt is NOT "absent": nothing proves the pane is idle, so it is
    # judged as unsatisfied and the lane stops before injecting (2026-10-26 review).
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
  if [ "$satisfied" = "false" ] || [ "$satisfied" = "unreadable" ] || [ "$wait_rc" != "0" ]; then
    # Orca names the prompt an agent stopped at (`wait.blockedReason`): say it, and never answer
    # it for the operator. A trust prompt is a grant only the operator gives (#596).
    blocked=$(pyjson "$tw" <<'PY'
import json, re, sys
try:
    d = strict_load(sys.argv[1])
except Exception:
    raise SystemExit(0)
r = d.get("result", d) if isinstance(d, dict) else {}
w = r.get("wait") if isinstance(r, dict) else None
reason = w.get("blockedReason") if isinstance(w, dict) else None
print(reason if isinstance(reason, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", reason) else "")
PY
)
    if [ -n "$blocked" ]; then
      _hint="the agent is waiting on its own prompt, so no preamble was injected"
      case "$blocked" in
        agent-trust-workspace) _hint="${_hint}: it asks whether to trust this folder, a grant only you give — answer it in the pane or trust the folder once in a plain terminal, then close this pane and re-run" ;;
      esac
      echo "SPAWN=FAILED task=${task} step=${step} rc=1 — terminal wait unsatisfied (wait.satisfied=${satisfied}, cli_rc=${wait_rc}, blockedReason=${blocked}); ${_hint}. Inspect: ${ORCA_BIN} terminal read --terminal ${h} --screen" >&2
      exit 1
    fi
    echo "SPAWN=FAILED task=${task} step=${step} rc=1 — terminal wait unsatisfied (wait.satisfied=${satisfied}, cli_rc=${wait_rc}); the TUI never went idle, so an injected preamble would land in a booting pane. Inspect: ${ORCA_BIN} terminal read --terminal ${h} --screen" >&2
    exit 1
  fi
  sleep "$SETTLE_SECS"  # let the TUI settle so it can receive the paste

  step=dispatch-inject
  # --inject SUBMITS the preamble; it does not merely paste it. The --json receipt carries
  # result.prompt{requestId, stages}. There is no Enter to send after this.
  dj="$SP/dispatch-$safe_title.json"
  # The receipt is the verdict here too: a typed refusal is a policy answer (exit 2, like the
  # supervised lane) and keeps its code, reason and the runtime's own nextSteps. Orca 1.4.229
  # refused one with `inject_rejected` / `no_agent_detected`, and this lane said only that the
  # step failed (#596).
  dj_rc=0
  "$ORCA_BIN" orchestration dispatch --task "$task" --to "$h" --inject ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$dj" || dj_rc=$?
  classify_dispatch() {
    pyjson "$1" <<'PY'
import json, sys
POLICY_CODES = {"task_not_found", "task_not_startable", "inject_rejected",
                "nested_worker_depth_exceeded", "consumer_fenced", "dispatch_inactive"}


def _f(v):
    """A receipt field, inert and on one line (W4-11): anything unprintable escaped."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(v))


try:
    d = strict_load(sys.argv[1])
except Exception:
    raise SystemExit(0)
if not isinstance(d, dict):
    raise SystemExit(0)
r = d.get("result") if isinstance(d.get("result"), dict) else {}
err = d.get("error") or r.get("error")
if not err:
    raise SystemExit(0)
if not isinstance(err, dict):
    err = {"code": str(err)}
data = err.get("data") if isinstance(err.get("data"), dict) else {}
for step in data.get("nextSteps") or []:
    print(f"nextStep: {_f(step)}", file=sys.stderr)
code = _f(err.get("code") or "unknown")
reason = _f(data.get("reason")) if isinstance(data.get("reason"), str) else ""
msg = _f(" ".join(str(err.get("message") or "").split())[:300])
verdict = "refused" if code in POLICY_CODES else "failed"
print(f"{verdict} CODE={code}" + (f" reason={reason}" if reason else "") + f" — {msg}")
PY
  }
  dj_err=$(classify_dispatch "$dj")
  # #680: Orca proves a TUI agent present by its pane or tab title or its foreground process
  # name. Claude Code's native installer runs ~/.local/share/claude/versions/<version>, so the
  # kernel names the process `<version>`, and an idle Claude sets no title; `--inject` therefore
  # answers no_agent_detected for a live claude pane (Orca 1.4.229 to 1.4.240). Orca's own
  # nextStep is a dispatch without --inject and the prompt by `terminal send`. This lane takes it
  # ONLY for the certified row (PROFILE=ro claude, no override), and only after Orca's spawn
  # record names the pane's agent claude AND its screen shows Claude's prompt in plan mode:
  # typed into a shell instead, a preamble would run as commands.
  fallback_skip=""
  case "$dj_err" in
    "refused CODE=inject_rejected reason=no_agent_detected "*)
      if [ -n "$override" ] || [ "$PROFILE" != "ro" ] || [ "$agent" != "claude" ]; then
        fallback_skip="the no-inject fallback covers only PROFILE=ro claude without an override"
      else
        step=confirm-agent
        ts="$SP/show-$safe_title.json"
        "$ORCA_BIN" terminal show --terminal "$h" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$ts" 2>&1 || true
        fallback_skip=$(pyjson "$ts" <<'PY'
import json, sys
try:
    d = strict_load(sys.argv[1])
except Exception:
    print("terminal show gave no readable record")
    raise SystemExit(0)
r = d.get("result", d) if isinstance(d, dict) else {}
t = r.get("terminal", r) if isinstance(r, dict) else None
if not isinstance(t, dict) or d.get("error"):
    print("terminal show gave no terminal record")
    raise SystemExit(0)
ident = t.get("agentIdentity")
if ident != "claude":
    print(f"Orca's spawn record names the pane's agent {ident!r}, not 'claude'")
    raise SystemExit(0)
preview = t.get("preview") if isinstance(t.get("preview"), str) else ""
tail = preview[-2000:]
# Claude Code's idle composer: the prompt glyph, and the ro row's own plan-mode footer.
if "\u276f" not in tail or "plan mode on" not in tail:
    print("the pane's screen does not show Claude's prompt in plan mode")
PY
)
      fi
      if [ -z "$fallback_skip" ]; then
        step=dispatch-no-inject
        dd="$SP/dispatch-noinject-$safe_title.json"
        dd_rc=0
        "$ORCA_BIN" orchestration dispatch --task "$task" --to "$h" --return-preamble ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$dd" || dd_rc=$?
        dd_err=$(classify_dispatch "$dd")
        case "$dd_err" in
          "refused "*)
            echo "SPAWN=REFUSED task=${task} dispatch (no --inject, after inject_rejected/no_agent_detected) ${dd_err#refused } (nothing was sent; receipts $dj and $dd; the agent pane ${h} is still open: inspect it, never resend)" >&2
            exit 2 ;;
          "failed "*)
            echo "SPAWN=FAILED task=${task} step=${step} rc=1 — dispatch (no --inject) ${dd_err#failed } (receipts $dj and $dd)" >&2
            exit 1 ;;
        esac
        pf="$SP/preamble-$safe_title.txt"
        if [ "$dd_rc" != "0" ] || ! pyjson "$dd" "$pf" <<'PY'
import json, sys
d = strict_load(sys.argv[1])
r = d.get("result", d) if isinstance(d, dict) else {}
pre = r.get("preamble") if isinstance(r, dict) else None
if not isinstance(r.get("dispatch"), dict) or not isinstance(pre, str) or not pre.strip():
    raise SystemExit(1)
open(sys.argv[2], "w").write(pre)
PY
        then
          echo "SPAWN=FAILED task=${task} step=${step} rc=${dd_rc} — dispatch (no --inject) returned no dispatch record or no preamble (receipts $dj and $dd)" >&2
          exit 1
        fi
        step=terminal-send
        ds="$SP/send-$safe_title.json"
        ds_rc=0
        "$ORCA_BIN" terminal send --terminal "$h" --text "$(cat "$pf")" --enter --wait-submit "$SUBMIT_SECS" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$ds" || ds_rc=$?
        ds_err=$(classify_dispatch "$ds")
        if [ -n "$ds_err" ] || [ "$ds_rc" != "0" ]; then
          echo "SPAWN=FAILED task=${task} step=${step} rc=${ds_rc} — terminal send of the dispatch's preamble ${ds_err:-exited ${ds_rc}} (receipts $dd and $ds; the agent pane ${h} may hold part of it: inspect it, never resend)" >&2
          exit 1
        fi
        echo "SPAWN=NOTE task=${task} dispatch --inject answered inject_rejected/no_agent_detected for a pane Orca names claude, showing Claude's plan-mode prompt; the preamble of a dispatch without --inject was delivered by terminal send, Orca's own nextStep (#680). Receipts: $dj, $dd, $ds" >&2
        dj="$ds"
        dj_err=""
        dj_rc=0
      fi
      ;;
  esac
  case "$dj_err" in
    "refused "*)
      echo "SPAWN=REFUSED task=${task} dispatch --inject ${dj_err#refused } (policy/usage — nextSteps above; nothing was injected; receipt in $dj; the agent pane ${h} is still open: inspect it, never resend)${fallback_skip:+; no-inject fallback not taken: ${fallback_skip}}" >&2
      exit 2 ;;
    "failed "*)
      echo "SPAWN=FAILED task=${task} step=${step} rc=1 — dispatch --inject ${dj_err#failed } (receipt in $dj)" >&2
      exit 1 ;;
  esac
  if [ "$dj_rc" != "0" ]; then
    echo "SPAWN=FAILED task=${task} step=${step} rc=${dj_rc} — dispatch --inject exited ${dj_rc} with no readable receipt (in $dj)" >&2
    exit 1
  fi

  step=read-inject-receipt
  read_stages() {
    pyjson "$1" <<'PY'
import json, sys
def _f(v):
    """A receipt field, inert and on one line (W4-11): anything unprintable escaped."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(v))
try:
    d = strict_load(sys.argv[1])
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
stages = [_f(s).replace(",", "\\u002c").replace(" ", "\\u0020") for s in stages
          if isinstance(s, str)] if isinstance(stages, list) else []
req = p.get("requestId")
print("STAGES=" + ",".join(stages) + " REQUEST=" + (_f(req).replace(" ", "\\u0020") if isinstance(req, str) else ""))
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
