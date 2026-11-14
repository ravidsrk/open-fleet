---
name: migrate-it
description: >-
  Land a stateful schema or data change across deploys with old and new code valid at every step:
  expand → dual-write → backfill → switch reads → zero-readers → retire-writes → zero-writers →
  contract, each phase its own deployed and baked change, each with a down path that was written AND
  run, dual-validity proven both directions, and a parity probe GREEN after backfill and archived
  before the old shape is dropped. The unit is one migration PHASE of one table or shape. Use when "migrate the
  database", "rename this column safely", "expand/contract migration", "backfill this table",
  "split this table without downtime", "we cannot take downtime for this schema change", or a
  stateful dependency upgrade. Not for ordinary feature delivery through one release (ship-it),
  code-only dependency or framework currency (modernize-it), restructuring code behind unchanged
  behaviour (reshape-it), or a backlog of findings (clean-sweep).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, t3code, ao+). git + gh. The project's own
  migration runner and a database the fleet can migrate and dump (a schema-dump command is the
  down-path oracle), plus a deploy path per phase and read/write telemetry for the zero-reader
  window. One worker playbook pack per worker (matt or addy) — never two routers in one worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one migration phase of one table or shape
  state_machine: expand → dual-write → backfill → switch reads → zero-readers → retire-writes →
    zero-writers → contract
  convergence: data parity holds and zero readers AND writers of the old shape remain, across deploys
  ordering: strictly phased — a phase never starts before its predecessor is proven in production
  parking: MIGRATED-WITH-PARKED, or ABANDONED with the expand rolled back
  oracle: data parity between the two shapes plus zero-old-shape-reader and zero-old-shape-writer
    queries, never the repo suite
---

# migrate-it — a stateful shape change landed across deploys, nothing ever invalid

You are the **COORDINATOR** of a migration run. The outcome is a schema or data shape moved with
**old and new code valid against the schema at every step**, proven — not a migration file merged.
Thin loop-holder: you plan the phases, dispatch one phase at a time, verify against authoritative
state (the dumped schema, the parity probe, the deploy record), and keep the ledger FILE (your
memory is compacted; the ledger survives). You never write migrations, review, or merge.

Read [ARCHITECTURE.md](references/ARCHITECTURE.md) once. Composes `decide-and-freeze` (FREEZE is the one-way gate), `data-migration` (the phase contract), `remediate-finding` (each phase is built and closed as one unit), `acceptance-review`
(build-blind review per phase); rides `evidence-manifest` (per phase: base → head SHA, the down round-trip diff, the parity probe, both dual-validity runs),
`merge-serialization` (the migrations directory is a merge chain), `reviewed-sha-freshness`, `dispatch-lifecycle`, `ledger-contract`, `attention-budget`, `sandbox-policy`,
`gate-classification` (every phase's promotion and deploy, and CONTRACT, are one-way). Worker TASK pack: one of matt | addy — never co-mount.

DEFERRED READS, never at activation: release.md at the first PROMOTE (its states run once per PHASE, never once per run; its recorded-grant
deploy rule governs every phase) · completion-audit.md at the first BAKE (bake and zero-reader criteria classified by verification mode) ·
compound-learn.md at VERDICT · liveness-resume.md on a stall/resume.

## Three terminal outcomes

- **MIGRATED** — pre-drop complete parity archived on the frozen set, old-shape readers/writers
  zero over the declared window, removal verified, contract merged, down-path evidence retained.
- **MIGRATED-WITH-PARKED** (degraded) — the ladder is complete up to a phase whose bake or
  zero-reader evidence the fleet cannot reach: `CODE_CLOSED` + `VERIFY_AT_SCALE` naming the query
  and the window, or a `needs-human` one-way gate. Never reported as MIGRATED.
- **ABANDONED** (degraded) — the migration is rolled back down the ladder using the exercised down paths,
  with the state it was returned to receipted. A migration left half-expanded is not a terminal.

## Pipeline

```
SELF-ORIENT → PLAN the TABLE SET and the phase list per table (one row per phase, with its down path), from the
  surface the code actually reads — a table nobody reads is not in the set.
→ FREEZE (decide-and-freeze, ONE-WAY): the human confirms the set and its ladder; headless/spawned
  publishes the proposal and PARKS. The set never grows mid-run (a new table is the NEXT run).
→ PER PHASE, strictly serial per table (data-migration.md):
    EXPAND → DUAL-WRITE → BACKFILL (batched, throttled, resumable; parity probe) → SWITCH-READS →
    ZERO-READERS → RETIRE-WRITES → ZERO-WRITERS → CONTRACT — each code rung its own deploy, baked
  each phase: BOOTSTRAP its BASE off the current default ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py"
  --mission migrate-it --base <BASE> --fork-point <sha>; BASE ≠ default — dispatch-lifecycle.md) → build (one
  unit, one PR against BASE) → down written and RUN (schema dump diff empty) → dual-validity both
  directions → build-blind REVIEW → LAND → PROMOTE (release.md: this phase's promotion PR) → PARK
  for the human's merge + recorded deploy grant (`gate-create` holds the next phase) → DEPLOY under
  that grant (deployed revision == the phase SHA) → BAKE, then the next phase. Observation rungs
  paste their window instead. Never two phases of one table in flight.
→ RESUME: a run that winds down at a grant reports `PARKED <table>:<phase>`, not a terminal; RESUME (liveness-resume.md) re-enters
  there once the merge is on default, the grant is in DECISIONS (`decisions.py append --source human:<who>`) and the deploy names the phase SHA.
→ PARITY: re-probe after the last backfill batch and at SWITCH-READS; any mismatch resumes the
  backfill from its cursor and re-probes — it does not restart, and it does not advance.
→ ZERO-READERS: paste the declared window; keep dual writes until the pre-drop parity archive.
→ RETIRE-WRITES: archive parity while still dual, then DEPLOY the retirement; zero use is observed
  FROM that deploy, so it cannot share a rung with the drop. ZERO-WRITERS: paste that window too.
→ CONTRACT: drop in a separate deploy/PR behind the one-way human gate; removal verified.
→ VERDICT + `compound-learn`: MIGRATED / MIGRATED-WITH-PARKED / ABANDONED.
```

## Convergence proof (definition of done)

Each phase: exercise the down path in a fixture (up/down schema diff EMPTY), prove both rollout
revisions compatible with the phase's before/after schema, deploy and bake. Irreversible recovery
is declared and human-gated, never asserted from a schema-only diff. Apply the phase oracle:

| Phase | Required evidence before advancing |
|---|---|
| EXPAND | Additive schema and compatibility; existing rows may have an empty new shape |
| DUAL-WRITE | Inserts/updates after activation agree in both shapes; historical rows await backfill |
| BACKFILL / SWITCH-READS | Cursor complete; full transformed-data parity on the frozen set, re-probed at switch |
| RETIRE-WRITES / ZERO-WRITERS | Parity archived while dual; retirement deployed; no writer over the window |
| CONTRACT | Archived pre-drop parity; zero old readers/writers over their windows; schema proves removal |

Parity includes row counts, a complete mismatch check, and seeded sampled hashes of transformed
values; counts/samples alone cannot claim 100%. Bind receipts to the phase SHA, data boundary and
probe/seed. After removal, verify the archive and surviving shape; never query a dropped column. The
verifier re-derives evidence without re-applying a landed migration. Executable populated SQLite
walkthrough is fixture proof; it never replaces production telemetry.

## Ledger + supervision

Header at T0 per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (SOURCE = the frozen table
set + phase count; BASE and FORK_POINT re-recorded at each phase's bootstrap; `WIP: builders=<n> reviewers=<n>` sized to
attention-budget.md — real WIP is one phase per table, so the cap is usually the table count). One row per PHASE:

`| task_id | table | phase | DOWN_RUN | DUAL_OK | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | PROMOTED | DEPLOYED | BAKED | PARITY | WT_CLEAN | lighting | park | evidence |`

Stalls → liveness-resume.md WATCH; a dead coordinator RESUMES from the ledger and the dumped
schema, never from narration — the schema on disk says which phase actually landed.

## Gates

FREEZE, every phase's promotion and deploy, and CONTRACT (the drop) are one-way human gates per gate-classification.md — as is
any irreversible phase declared in its PR body. Each needs a recorded human grant, never a default: the fleet opens that phase's
promotion PR and parks; it never merges it or self-authorizes a deploy. A window the fleet cannot observe is `CODE_CLOSED` +
`VERIFY_AT_SCALE` with the exact query, never an assumed pass.

## Anti-patterns

Renaming or dropping a shape in place ("it's one line") — during the rollout old and new code run together and one queries
a shape that is gone. Merging a phase whose down path exists but was never run. Shipping the additive step and the code that
depends on it in one deploy. A single `UPDATE` across millions of rows (it locks the table; batch, throttle, resume).
Restarting a failed backfill instead of resuming from its cursor. Declaring parity from row counts alone (equal counts with
wrong values is exactly what the sampled hash exists to catch). Dropping the old shape because "nothing should read it"
without the zero-reader window's telemetry. Two migrations on one table in flight. Treating a deploy revert as a data
revert. Letting the frozen table set grow mid-run. Promoting or deploying a phase on the fleet's own authority.

## Related

`ship-it` (ordinary feature delivery; cross-deploy stateful work hands here, while a single additive schema slice can use
the phase contract inside its wave), `modernize-it` (code-only currency; it hands a data-shape change here explicitly),
`reshape-it` (code restructured behind unchanged behaviour — no data at risk), `clean-sweep` (a findings backlog),
`root-cause` (why the data is wrong; this mission moves it, it does not diagnose it).

Bundled copy of `migrate-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
