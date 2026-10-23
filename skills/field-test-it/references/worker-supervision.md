# Runtime policy — worker supervision (live workers and supervision failures)

What the coordinator owes its workers while they run, and how it recovers when
supervision itself breaks. Dispatch mechanics, the worker contract, and inbox
handling stay in dispatch-lifecycle.md; dead-worker respawn, reflection, and
coordinator-death RESUME stay in liveness-resume.md. This file covers only the
gaps between them: budgets, stuck-but-alive workers, transcribing deliveries,
and re-binding a fenced-but-alive coordinator. Adoption is per mission via
deferred reads (liveness-resume.md precedent), not catalog-wide: the MUSTs
below bind coordinators running under a mission that composes this doc.

Evidence level: **ASSERTED.** Generalized from one field run (the 2026-09-14
clean-sweep tracker, `docs/runs/2026-09-14-clean-sweep-tracker.md`): a
transcript-frozen reviewer, a verdict wedged on a dead provider stream, and two
coordinator fencings. The mechanisms are designed to survive re-witness; the
thresholds below are starting values, not measurements.

## Per-dispatch budgets (every TASK carries one)

A dispatch without a budget is a wait without an end. Every worker TASK states
a timebox and a partial-report STOP: past the box with no `worker_done`, the
worker reports what is green, what remains, and the exact SHAs — it does not
go silent. A worker past its STOP with no report is STUCK, not slow: act,
don't wait. Budgets are per dispatch, sized to the work (a review axis needs
less than a build); the coordinator picks the number at dispatch and the
ledger records misses.

## The stuck-but-alive ladder

liveness-resume.md governs the dead (`exited`, failed start) and the
unverifiable (absence authorizes nothing). A third state exists: the agent is
*alive* but wedged — typically inside one hung tool call, unable to process
anything further. Positive evidence of wedgedness is a frozen transcript past
the dispatch STOP plus an unanswered nudge — that is presence, not absence,
and it authorizes the ladder (never a release or evidence abandon: the
transcript persists and stays citable):

1. **Inspect:** read the transcript tail (`worker-read --dispatch <id>`) and
   the run's attention rows (`worker-list --run <id>`). Name what it is stuck
   in, with the timestamp of last movement. For remote workers add
   `--include-remote` — `worker-list` reads local fleet state only, and every
   remote worker without it renders `unverifiable` (`orchestration-worker-specs.ts:125`).
2. **Nudge:** one `send` to `dispatch:<id>` — finish-or-report now, no new
   experiments. A nudge the agent cannot process (still inside the hung call)
   is itself the confirmation.
3. **Stop:** past one more window with no movement, `worker-stop`. The frozen
   transcript is evidence of the wedge, not a verdict on the work.
4. **Re-dispatch fresh** with guardrails baked into the new TASK (a timeout on
   every scratch/test run, a report-by deadline earlier than the box), the
   liveness-resume.md reflection line written first, and a sanitized, bounded
   (`<= 40` lines) Failure Handover Packet built via `"$OPEN_FLEET_ROOT/runtime/scripts/watchdog.py" --handover <attempt>.json`
   so the replacement worker receives the exact failing command and error delta without
   inheriting the dead session's noisy transcript. A retry that repeats the
   same shape without guardrails is the identical-error class (`HANDOVER_ACTION=KILL_OR_PARK`):
   kill it, don't loop it.

## Watchdog: what is mechanized, what stays manual

`"$OPEN_FLEET_ROOT/runtime/scripts/watchdog.py" --heartbeats <snapshot>.json --dry-run`
(classify only; drop `--dry-run` and add `--state`/`--log` for live) polls
worker heartbeats and classifies OK / SLOW / HUNG / WEDGED per the ladder:
past-STOP silence is HUNG, an explicit wedge marker (or frozen-past-STOP
plus an unanswered nudge) is WEDGED, slow-but-alive is not stuck. A heartbeat
whose `dispatched_at`/`last_movement_at` is missing, empty, unparseable or in the
future cannot be judged: exit 2, naming the worker — never a silent idle 0. Every
threshold lives in `"$OPEN_FLEET_ROOT/runtime/watchdog.json"` — tunable without code edits.

Owned by the watchdog: classification, one auto-nudge per HUNG worker
(finish-or-report, no new experiments), the stop-redispatch
RECOMMENDATION with JSONL evidence (run/worker ids, timestamps) on
still-HUNG or WEDGED, and formatting a sanitized Failure Handover Packet
(`watchdog.py --handover <attempt>.json`, enforcing the reflection gate and
identical-error kill before `worker-start --retry-of`). Nudge rate limits: at most 1 nudge per dispatch, 1
per worker per hour, one window between nudges — a flapping worker cannot
cause a nudge storm. A CI-failure nudge has its own per-dispatch budget
(`max_ci_nudges_per_dispatch`, default 1) and fires once per distinct failure
signature, so it never spends the hang nudge; the hourly cap and window count
both kinds — a hang nudge held back only by a CI nudge is deferred, not escalated.

Heartbeat inputs beyond liveness (the snapshot the coordinator assembles):

- `ci_checks`: `[{name, step, conclusion, exit_code}]` from the worker's PR
  checks (the coordinator maps e.g. `gh pr checks --json name,state` rows,
  `state` -> `conclusion`); passing and still-pending (`in_progress`, `PENDING`,
  `QUEUED`…) rows are ignored, run ids and log URLs never enter the signature.
  No producer ships in-repo: absent means no CI nudge.
- `waiting_input`: `true` while the worker has an open HITL question. The
  coordinator may set it; when absent and `OPEN_FLEET_STATE_DB` names an
  existing local-state DB, the watchdog derives it by reading that DB strictly
  read-only (no side files, no migration), matching gate/question senders on
  the dispatch's terminal handle, dispatch id and worker id; an unreadable DB
  is a warning, never an abort. It suppresses the nudge only — the worker is
  still classified, and WEDGED / still-HUNG is still recommended.

Stays manual, always: the stop, the re-dispatch (dispatch spends money and
mutates run state), coordinator re-bind after fencing, and every verdict on
the work itself. A recommendation is a decision trail for the coordinator,
not an action taken.

## Transcribe at delivery

The message store is a QUEUE, not an archive: a runtime reset purged it once,
and a re-binding replays unacked history the coordinator may already have
acted on. At every Delivery, before `--ack`, persist each `worker_done` and
`question` to the run-scoped transcript artifact: one JSON file per message
at `<run-archive>/transcripts/<delivery-id>/<msg-id>.json` carrying `{id,
type, created_at, taskId, dispatchId, subject, body, payload}`, written
beside the ledger (durable, run-scoped — `/tmp` satisfies "outside the
store" and fails "durable"). Re-bind matches replays against these files by
message id before acting, so a replay never re-triggers work and a purge
costs nothing.

## Coordinator re-bind (fenced-but-alive)

RESUME (liveness-resume.md) is for a dead coordinator. A different failure
keeps the process alive but drops its binding: `check` answers
`stable_pane_required`, then `consumer_fenced`, while dispatched workers keep
running. Recovery, same session, workers untouched:

1. Confirm the old binding is fenced (the fence itself is the FREEZE-check —
   a live old coordinator plus a new one is the dual-writer class).
2. Adopt a terminal with a stable pane: a fresh `terminal create`, or a live
   RETAINED worker terminal (settled dispatch, idle agent — never an active
   worker's). Bind it with `run-use --id <run> --from <handle>` and verify
   with one `check`.
3. Expect store thinning: the new binding replays unacked batches (match to
   transcripts per the section above) and may find the store purged (the
   transcripts plus git state rebuild it). Record the generation change and
   the new coordinator handle in the ledger header.

## Coordinator verification discipline

The coordinator is a failure point with the same shape as its workers, so the
same rules bind it: IDs and SHAs are pasted from command output, never written
from memory (a guessed suffix is a fabricated SHA — verify with `rev-parse`
before it enters a spec or the ledger); gate output is captured WHOLE (full
logs, never tails — a tail swallows the summary line the close needs); and a
ledger slip, once found, is corrected in-ledger with the wrong value named,
not silently rewritten.
