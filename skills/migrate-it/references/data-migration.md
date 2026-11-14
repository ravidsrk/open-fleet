# Playbook — data-migration  (expand → dual-write → backfill → switch → contract, phase by phase)

Recipe: Addy `deprecation-and-migration` expand/contract schema rules; the expand–contract
slicing and the review lens are stated as fleet rules below. The unit is ONE phase of ONE table or shape — a
deploy-gated step, not a slice. Data is the one thing a reverted deploy does not roll back, so the
rule is absolute: **never change a shape in place; old and new code must both be valid against the
schema at every step**. `migrate-it` runs a table through the whole ladder; a single-phase schema
slice inside a build wave runs the same phase contract.

## The phase ladder (each phase is its own deploy)

```
EXPAND        add the new column/table/index, nullable, beside the old one   [deploy + bake]
DUAL-WRITE    the app writes BOTH shapes on every insert/update              [deploy + bake]
BACKFILL      copy old → new for existing rows, batched + throttled          [job, resumable]
SWITCH-READS  reads move to the new shape, writes stay dual                  [deploy + bake]
ZERO-READERS  telemetry shows no reader of the old shape over the window     [observation]
RETIRE-WRITES old writers retired; parity archived first, while still dual [deploy + bake]
ZERO-WRITERS  telemetry shows no writer of the old shape over the window     [observation]
CONTRACT      DROP the old shape; removal verified against the archive      [one-way, human]
```

Additive first, destructive last and alone. Adds are safe in any deploy; drops and renames get their
own deploy AFTER no code references the old shape. Two rungs in one phase is the coupling this
prevents: old and new code run together and one queries a shape that is gone. Retiring writers and
dropping together is that error — zero use is observed FROM a deploy, so combined none can appear.

## `down` is written AND run before the phase merges

A down path never run is a deploy that cannot be reversed. Per phase, before the PR is mergeable:
run `up`, then `down`, dump the schema and diff it against the pre-`up` dump — **the diff must be
empty**. Paste the command and that diff into the manifest; a `down` that merely exists is not
evidence. An irreversible phase (data destroyed) is declared so in the PR body and becomes a
one-way human gate, never a silent exception.

## Dual-validity, proven both directions

- **old code vs new schema** — the pre-phase application revision run against the migrated schema.
- **new code vs old schema** — the phase's application revision run against the un-migrated schema
  (what a rollback lands on).

Split a phase whose new code cannot boot on the pre-phase schema. At CONTRACT, both rollout
revisions must already use only the new shape; "old code" means pre-drop code, not pre-expand code.

## Index and lock rules

Large indexes are built without blocking writes (Postgres `CREATE INDEX CONCURRENTLY`, and its
engine-specific equivalents — name the engine and the mechanism in the ledger). Adds are nullable
with no default rewrite where the engine rewrites the table for one. No `ALTER` that takes an
exclusive lock on a hot table inside a deploy step; that is its own throttled operation with a
stated lock-time budget and an abort rule.

## Backfill: batched, throttled, resumable

The backfill is a job, not a migration file: a single `UPDATE` over millions of rows locks the
table. It processes a bounded batch by an ordered key, records the last committed key as its resume
cursor, sleeps a throttle between batches, and watches replica lag or the equivalent saturation
signal — over the ceiling it backs off, it does not power through. A failed batch **resumes from
the cursor; it never restarts** — a restart re-does completed work and, on a non-idempotent copy,
corrupts what it already wrote. Every write is idempotent, so re-running a batch is a no-op.

## Phase oracle

EXPAND proves additive schema/compatibility; historical rows may have an empty new shape.
DUAL-WRITE proves parity of inserts/updates after activation; historical rows await backfill.
BACKFILL completes its cursor and probes the frozen set; re-probe at SWITCH-READS:

```
rows_old=<n> rows_new=<n>            equal on the frozen table set
mismatches=<full comparison>        any transformed-value mismatch = RED; resume backfill
sample=<k rows, seeded, ordered>    matching transformed-value hashes; diagnostics, not 100% proof
```

Bind each probe to phase SHA, data boundary and seed. RETIRE-WRITES archives full parity while
writes are still dual, then deploys the retirement; ZERO-WRITERS observes that deploy. After DROP,
verify the archive, surviving shape and schema removal; query no dropped column.

## Cutover is decoupled from the deploy

Where the read switch is risky, it moves behind a flag so the cutover is a config change, not a
release: flip, watch, flip back. The flag's removal is its own later change. Bake and the zero-use
windows need production telemetry the fleet may not have — where it does not, the phase merges
`CODE_CLOSED` with a `VERIFY_AT_SCALE` item naming the exact query and window, never a claimed green.

## Completion (per phase)

One deployable phase; exercised down path (schema diff empty, data recovery separately proven or
human-gated as irreversible); both compatibility checks and that phase's oracle above green;
engine-specific index/lock rules named. Missing window telemetry parks the phase. CONTRACT has the
archive, both zero-use windows, removal evidence and a human gate. One phase per table in flight.
