# Runtime policy — Orca DAG semantics (CLI / agent fleets)

Ground truth about how Orca's orchestration DAG behaves for fleets that drive it with CLI verbs
(`run-create` / `task-create` / `worker-start` / `check` / `send`). Sourced from live-DB research
plus the version-matched guide the binary serves (`orca skills get orchestration`); treat as
operational contract, not product marketing. Current schema line: v43 at the pin (`db/contract-constants.ts:23` at v1.4.239 / 47f77cf7, unchanged since v1.4.224 / 2bb20586; v42 was the v1.4.215 line — orca-session-id columns — and v43 only respells stored `session:<id>` addresses as `orca_session_id:<id>`, `migrate-v43.ts`).

## A Run is the durable scope primitive

`run-create` / `run-use` / `run-current` / `run-list` / `run-show` give the fleet a first-class
namespace and coordinator inbox. Every task belongs to one explicitly bound Run, and the scope
verbs honor it: `task-list --run <id>`, `worker-list --run <id>`, the coordinator's `check`. The
retired scheduler commands (`orchestration run`, `coordinator-start/stop`) perform no effects and
return the current-skill recovery action — never call them.

**Fleet rule:** the run scope is the Run id, recorded in the ledger header at start (liveness-resume.md).
Never converge, WATCH, or RESUME against an unfiltered `task-list` — unscoped lists are every past run on the
machine (nothing prunes automatically). A foreign run's completed tasks are not your wins; a foreign pending
is not your stall. (The v1.4.206 newest-first paging + truncation `warnings[]` is `worker-list`'s contract,
not `task-list`'s — `task-list` has no cursor or limit; liveness-resume.md carries the worker-list row.)

**Nested depth:** `nested_worker_depth_exceeded` is counted from the ISSUING terminal, not from the
Run — a dispatched worker creating a fresh Run and calling `worker-start` is still a worker, and
still blocked at the default depth of 1 (dispatch-lifecycle.md). Exception: a self-dispatch
(creator == assignee, context recorded against the coordinator's own terminal) is not a nesting
parent and consumes no depth (`dispatch-depth.ts:63-73`).

## DAG edges are `deps`, not `parent_id`

`tasks.deps` (JSON array of task ids) is the dependency graph the runtime promotes against.
`parent_id` is a decomposition hierarchy that is empty in real CLI fleets **only because the
fleet never sets it** — `task-create --parent <task_id>` and `worker-start --parent` do exist
and do write it, validated to the same Run, and worker-terminal listing/attention queries read
it (`cli/specs/orchestration.ts:136`, `task-store.ts:32-35` at v1.4.203 — re-witnessed by docs/runs/2026-09-16-pin-it-416/). Do not build or verify fleets
on parent/child nesting, but do not call the column unwritable either.

**Fleet rule:** materialize and verify only via `--deps` and returned task ids
(decompose-dag.md). The stuck-pending trap (liveness-resume.md) is about deps, not parents.

## What the message enum lies about

These `MessageType` values exist in the schema but **nothing writes them** on CLI/agent paths:

| Type | Reality |
|------|---------|
| `dispatch` | Prompt is injected into the worker PTY; no message row. Reconstruct from the dispatch record + `tasks.spec`. |
| `handoff` | Unused by the runtime. |

`merge_ready` is **fleet-written** (merge-serialization.md), not a phantom type — the runtime
delivers it but triggers no built-in merge behavior. Expect it during serialized merges.

What *is* real and load-bearing: `worker_done`, `merge_ready`, `heartbeat`, `question`,
`escalation`, `status`. `decision_gate`, `dispatch` and `handoff` are all valid `send --type`
values a fleet *could* write (`cli/specs/orchestration.ts:71` lists all nine); the runtime writes a
`decision_gate` only on the legacy direct-ask path (`legacy-ask-operation.ts:101`) and migrates
existing ones to `status` (`message-inbox.ts:81`, :82 at v1.4.239), and writes no `dispatch` or `handoff` at all.
`decision_gate` sat in the load-bearing list until #302 — not because the CLI refuses it, which is
what that issue supposed, but because the runtime has stopped producing it.

**`--types` is the WAKE CONDITION, not a filter.** `check --wait --types worker_done,escalation`
decides when the waiter wakes; the Delivery it returns is always the **whole FIFO batch**, every
type included (`cli/specs/orchestration.ts:114`, `orchestration/messaging-and-gates:19-22` at v1.4.203). So
heartbeats never "bury" lifecycle mail — but a loop that handles only the filtered type and then
`--ack`s has just acknowledged the rest unprocessed. Process the whole Delivery, then ack
(dispatch-lifecycle.md).

## Delivery is batched, replayed, and acked

A coordinator `check` returns the Run's oldest FIFO **Delivery** (up to 50 messages) and replays
that exact batch until `--ack <delivery_id>` — the mailbox commits the delivery before waking the
coordinator, so a crash between receive and process never loses mail. Process the whole batch,
then ack. Every mutation accepts `--retry-request <id>` (`request-show` inspects): re-issuing with
the same id is deduped, so a lost response never double-dispatches. Edge (v41+, at the pin):
eligibility is unread-membership — a fully-read-but-unacked batch does not block the next insert
(`migrate-v41.ts:3-4`) — so ack still advances the mailbox, but a missing ack can no longer wedge it.

## Task status is current-state, not a timeline

`tasks.status` is overwritten in place by many writers. `pending → ready` promotion is
**silent and untimestamped**. Reconstructible facts: creation, each dispatch attempt
(latest = the active dispatch; failed `worker-start` attempts count across `--retry-of` toward `failure_count` at v1.4.229, and the circuit trips at 3 returning `task_not_startable` with `data.failureCount`, `worker-dispatch-outcome.ts:59-66`, `orchestration-dispatch-refusal-contract.ts:36-53`),
completion via `worker_done`.

**Fleet rule:** never grade progress from a reconstructed status history. Ledger + git +
evidence-manifest are the completion oracle. `worker_done` with matching `taskId`+`dispatchId`
from the owning pane auto-completes the task — do not also `task-update --status completed`.
A dispatch re-attaching after a restart surfaces `consumer_fenced` — the old coordinator is
fenced; only the current binding's calls mutate.

## Convergence (when the DAG is done)

A run is **converged** only when every task in the **Run's task set** is terminal
(`completed` or `failed`), no live worker ask is waiting on the coordinator (dispatched unit +
ask thread with no reply — not merely unread), and no `gate-create` hold remains for those tasks.
Not converged:

- any `pending` / `ready` / `dispatched` / `blocked` in scope
- live ask (dispatched unit, ask without reply) even if the message is already `read`
- a `pending` child whose dep **failed** or never existed (never auto-promotes — stuck-pending
  watchdog must surface it; a failed dep is a permanent strand, not a retry)

A finished foreign run in the same DB is irrelevant. All-green elsewhere is not your proof.

## Gates: live ask vs historical vs DAG hold

Two paths (gate-classification.md):

1. Worker / coordinator `ask` → a `question` **message** to the owning Run. The worker CLI
   **blocks until reply or timeout**; a timeout leaves the question PENDING — resume it with
   `ask --resume <message_id>` (the same id, never a duplicate ask). The task usually stays
   `dispatched` — `ask` does **not** flip it to `blocked`.
2. Coordinator `gate-create` → task status `blocked`; `gate-resolve` unblocks.

**Fleet rule — distinguish live from historical:**

| Case | How you know | Action |
|------|--------------|--------|
| **Live ask** | A worker unit is still `dispatched` and its `question` has **no reply** yet (do **not** rely on the unread bit alone — `check` marks read on receive) | **Always blocking inbox work.** Reply by `message id` (`reply --id`) promptly — do not wait for task status `blocked` (it will not come). Ignoring it burns the ask timeout. On RESUME, re-scan threads for asks without replies while the unit is still dispatched. |
| **Historical unanswered** | Unit already terminal / no waiting worker; ask with or without a reply left in history | **Not** a fleet stall. Do not spin the run waiting on it. |
| **DAG hold** | `gate-create` → task `blocked` | DAG blocker until `gate-resolve` or park as one-way human. |

Prefer `gate-create` for human one-way holds the DAG must respect; prefer `ask` for
worker→coordinator mechanical/taste questions. Answer asks by **message id**, never by guessing
a gate-table id.

## Completion receipts the DB retains

`worker_done.payload` and `tasks.result` are free-form TEXT. The fleet's SHA-bound evidence
manifest (evidence-manifest.md) is the definition of done; still make retained orchestration
history point at the same artifacts — but via the TYPED flags, `--report-path <path>` and
`--files-modified <csv>`, not a hand-rolled `reportPath` payload key. Upstream's own rule is
"prefer `--task-id`/`--dispatch-id`/etc. over raw `--payload` JSON" (`cli/specs/orchestration.ts:49,81` at
v1.4.203): PowerShell strips JSON quotes, and a typed flag cannot be misspelled silently.

## Explicit non-goals (do not import from visualizers)

Wave/idle-gap UI, process-liveness dots, conversation reconstruction, scoreboards — operator
tooling. Fleets own ledger + evidence, not a second event store.
