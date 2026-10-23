# Runtime policy — liveness and crash-resume

The runtime tracks everything needed to keep a long run alive and recoverable, but it only WARNS on stalls; the
fleet must act. Both live-supervision and crash-resume read the same persisted provenance (tasks,
dispatch_contexts with last_heartbeat_at/failure_count, worker_done payloads — all in SQLite, surviving restarts).

## Provenance is `taskId`+`dispatchId`, never the handle

Lifecycle authority is the payload's `taskId`+`dispatchId` verified against the dispatched pane — NOT a
terminal-handle comparison. A pane can receive a new handle after a restart, so never accept or reject a
`worker_done`/`heartbeat` by matching handles; the runtime ignores a lifecycle message sent from a different
pane than the one that owns the dispatch. When a handle returns `terminal_handle_stale`, re-resolve it with
`terminal list --worktree … --json` and continue with the replacement ONLY — never dual-send to the old and
new handles.

## Liveness authority: the projection, not the pane

`worker-list` is the ENUMERATING command and the authority on agent liveness. Each row carries
`projection.liveness` (the fleet verdict), `projection.attention.categories`,
`projection.attention.requiresAction`, and a literal `projection.nextAction.argv` to run. `worker-show`'s
`observation.status` is **PTY liveness only** — a `live` terminal can still hold an agent that died at a trust
prompt (`orchestration/recovery-and-cleanup:25-31` at v1.4.203). The fleet taught this inverted for two runs; the projection half is re-witnessed live at v1.4.203 (docs/runs/2026-09-16-pin-it-416/receipts/worker-list-unscoped.json).
it is the reason pane-reading felt authoritative.

Always scope it: `worker-list --run <run_id>`. Unscoped it reports every Dispatch this runtime ever recorded — ≥ v1.4.206 pages newest-first with a truncation `warnings[]`, but an unscoped page is still everyone's rows, not your run's: scope or the convergence math is fiction.

Two states the old vocabulary lacked, and neither is a failure:

- **`outcome_unknown`** — the start neither proved nor disproved the worker. Inspect, then choose
  `worker-stop` or an explicit `worker-abandon`. `spawn_worker.sh` exits **4** here and prints the receipt's
  `nextCommands`.
- **`unverifiable`** — absence, not a verdict (`missing_status`, `stale_status`, `restored_unconfirmed`,
  `host_unavailable`, a remote worker with no connection). Absence **authorizes nothing**: never stop,
  abandon, retry, or release on it. Keep waiting or inspect.

Leave a wait only on POSITIVE proof the agent stopped: `exited` liveness, the worker's own observation of
process exit, or a transcript whose final agent turn sent no `worker_done`.

## WATCH (self-healing while alive)

- Poll `check --wait --types worker_done,escalation,question` ({count:0} timeout is a checkup tick, not an
  error). `--types` is only the WAKE condition — the Delivery still carries the whole FIFO batch, so process
  every message before `--ack` (orca-dag-semantics.md). Keepalives (`{"_keepalive":true,…}`) go to **stderr**,
  never stdout — pipe stdout only into parsers (`"$OPEN_FLEET_ROOT/runtime/scripts/pm.py" <file>` for saved stdout streams).
- **After 3 empty waits, ask the runtime instead of guessing:** `worker-list --run <id> --json`, then act on
  every row whose `attention.requiresAction` is true by executing its literal `nextAction.argv` (`inspect` / `release` / `recover`). That argv is the runtime's own answer — running it beats any fleet heuristic, and an INSPECTING argv asks for evidence, not cleanup.
- Inspect without side effects: `check --format` renders rows as local text only (`orchestration.ts:115`); `gate-list --run <id>` lists a Run's gates without binding to it (`orchestration.ts:267-272`).
- End-of-run gate: `worker-list --run <id> --terminal-state reclaimable` — while any row is reclaimable,
  something still owes a decision. That, not a clean inbox, is "nothing outstanding".
- Respawn a dead worker: log the evidence + a doctor-owned attempt count (NOT the runtime failure budget) →
  **reflection-before-retry** (below) → `task-update → ready` ONLY after the evidence line → `worker-start --task
  <id> --retry-of <failed dispatch id>` with a fresh placement (`--worktree`/`--agent`/`--terminal`, never the
  dead one). spawn_worker.sh's contract: exit 2 = usage or policy refusal (bad args, unknown agent, unmet deps,
  danger without opt-in) — SURFACE it, never retry as uncounted re-triage; every typed refusal (`task_not_found`,
  `task_not_startable` with `data.unmetDependencies`, `inject_rejected`, `nested_worker_depth_exceeded`,
  `consumer_fenced`, `dispatch_inactive`) branches the same way, carrying `error.data.nextSteps`. Exit 5 = a LIVE
  worker whose `launch.effective` does not prove the PROFILE's flag — STOP it, fix the host, never respawn. Exit
  4 (`outcome_unknown`) is INSPECT, never respawn; exit 1 is an outright failed start — nothing live, retry per
  the reflection above. Exit 3 (custom-argv: input accepted, turn unproven) is a POSSIBLE false negative — READ
  THE PANE first (`orca terminal read --terminal <h> --screen` or `worker-read --dispatch <id>`), not by eye: a
  live TUI is a working worker and respawning beside it is a dual-writer (dispatch-lifecycle.md). A coordinator-side
  probe that cannot double-send: `terminal send --wait-submit <s>` observes the accepted prompt for the duration — a timeout returns the queued receipt and never resends (`terminal-send.ts:19-20`).
- BREAK at 3 doctor attempts OR the dispatch-context circuit break (3 consecutive failures marks the task
  failed) → escalate honestly (gate-classification.md).
- **Identical-error kill:** if the last ≥2 doctor attempts failed on the same error signature (same failing
  command + same primary error token), do NOT retry the same approach — kill, reassign to a fresh worker with
  a rewritten TASK, or park. Counted toward the 3-attempt cap.
- Re-confirm `ORCA_COORD_ALLOW_DANGER` before respawning a danger-profile worker.
- Lost preamble ≠ dead worker: `dispatch-show --task <id> --preamble` regenerates from the CURRENT spec, so
  its text is not necessarily the injected bytes — INSPECT with it, never replay it. 1.4.200 answers a
  regenerated replay with `request_mismatch` (receipts: `docs/runs/2026-09-12-runtime-repin/`). Replay only
  RETAINED ORIGINAL bytes; without them, inspect and leave the turn unproven. spawn_worker.sh takes the
  stricter line for its own lane and replays nothing. NEVER blind-re-Enter: `accepted: true` proves input
  acceptance, not a started turn, and the rule is never resend on silence.
- A worker blocked on a human prompt shows `observation.agentWait` — a gate-classification problem, not a
  respawn (null and absent differ: absent means the host never reported).
- NEVER run `orchestration reset --all|--tasks` mid-run — it wipes the task/dispatch state every recovery path
  below depends on. `--messages` spares tasks/dispatches but deletes inbox + question threads (`orchestration-reset.ts:80-90`); still no mid-run use — WATCH/RESUME fix everything it could.

## Reflection-before-retry (mandatory on doctor respawn)

Before every doctor-owned respawn, append to the unit's evidence / ledger:

```
REFLECTION: what failed? · what specific change would fix it? · am I repeating the same approach?
```

A respawn without that line is invalid — write it first. If the honest answer to the third question is yes,
apply the identical-error kill (reassign or park), do not loop.

## The stuck-pending watchdog (a runtime trap)

**Corrected:** `task-create` DOES validate `--deps` since upstream #9925 — a missing or foreign-Run dep throws
`Dependency task <id> must belong to run <run>` (`task-store.ts:38-43` at v1.4.203). The typo'd-dep strand
this file used to warn about cannot happen; a fleet that budgeted for it was defending a closed hole.

The other half is CURRENT and is the real trap: `promoteReadyTasks` fires only when a dep COMPLETES, and
requires every dep `completed`. A dep that ends **`failed`** therefore strands the child in `pending` FOREVER
— and convergence detection only flags `blocked`, never `pending`. That strand is permanent: it is not a retry
of the child. Every fleet keeps the watchdog for it — any task `pending` past a threshold with an unmet or
failed dep is surfaced, never silently waited on. Edges are `deps`; `parent_id` exists but the fleet does not
set it (orca-dag-semantics.md).

## Scope is never "the whole database"

The orchestration DB mixes every run on the machine. WATCH and RESUME operate only on the run's scope: the
**Run id** from the ledger header (`task-list --run`, `worker-list --run`, `check` all honor it) plus the
ledger's task ids. Unfiltered `task-list` is a discovery tool, not the run.

## The ledger header (every mission writes it; RESUME depends on it)

The FIRST line of every mission's ledger file is a header, written at run start and updated on coordinator
respawn:

`RUN: <orchestration Run id from run-create> · COORDINATOR: <terminal handle(s)> · BASE: <integration branch,
or '-' for report-only/planning missions> · FORK_POINT: <sha BASE was created from, or '-'> · T0: <ts> ·
SOURCE: <mission denominator ref + digest> · WIP: builders=<n> reviewers=<n>`

`RUN` and `COORDINATOR` are always required (RESUME dies without them); fields a mission class has no value
for are recorded as `-`, never omitted (a missing column is indistinguishable from a truncated header). `WIP`
is the run's attention cap (attention-budget.md — class defaults unless measured); a header without it
predates this field, and RESUME writes the class default back in before dispatching anything.

A ledger with rows but no header is a resume-orphan — recoverable only by hand.

Unit **boolean flags**, park classes (`CODE_CLOSED` / `VERIFY_AT_SCALE`), `docs/DECISIONS.md`, and the
**CONTEXT HANDOFF** block under compaction pressure: ledger-contract.md. RESUME always re-reads those before
trusting memory.

## RESUME (coordinator died)

Run scope is mandatory: the Run id + task ids from the ledger header. Everything else is
counted-but-untouched; no scope → resume ABORTS.

1. FREEZE-check: no other live coordinator.
2. Bind the run: the new coordinator adopts it with `run-use --id <run>` — and if the run predates an Orca contract
   update (legacy rows, authority labels on its mail), take it over explicitly with `run-use --id <run>
   --takeover-legacy` **from the live coordinator terminal** (upstream's adoption protocol preserves live workers'
   dispatches, processes, and filesystems and routes their later questions to the current coordinator — an Orca upgrade
   mid-run is no longer a hand-recovery). A dispatch re-attaching under a new coordinator shows `consumer_fenced`; the
   fenced old coordinator's mutations are rejected. Caveats: never take over while the ORIGINAL coordinator is still
   active (dual-writer with extra steps); `--from` cannot nominate the taker, so run it from the terminal that will hold
   the run; `run_legacy_local` is an empty tombstone — find the Run whose objective reads `Recovered orchestration work
   from a contract update`; when authority is unproven, degrade to read-only inspection rather than adopting
   (`orchestration/legacy-contract-migration:19-23,69-83` at v1.4.203).
3. REBUILD from provenance; CROSS-VERIFY every "completed" against git (evidence-manifest.md) —
   provenance-says-done + git-disagrees = SUSPECT (treat as failed).
4. RECONCILE the ledger (git is truth, the ledger is its cache).
5. RE-ENTER the mission loop at the DAG frontier; never re-do a verified-merged unit.

## Inflation post-mortem (re-runs — the Aula lesson)

SUSPECT covers crash-resume inside one run; this covers run N+1. A run re-entering a surface a PRIOR run
reported done starts by re-reading that run's completion report and listing every claim whose proof was "CI
green" rather than a verified end state as the FIRST items of the new work index, re-confirmed OPEN until the
verifier passes them against authoritative state. An autonomous run will otherwise believe its own green
checkmarks — anti-inflation has to be structural, not a reminder.
