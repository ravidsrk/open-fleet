# Runtime policy — ledger contract (boolean gates, handoff, park classes)

The ledger file is the coordinator's external brain. Progress advances only when flags read true
**in the file**, not when the coordinator "believes" a unit is done. Header shape and RESUME scope
live in liveness-resume.md; this policy is the row schema and mid-run handoff.

## Phase marker (mutating missions)

First content line after the header (or a dedicated `PHASE:` field on the header) is the lifecycle
marker. Advance only forward; never re-open a frozen phase:

`ORIENT → FREEZE → BUILDING → PROVING → SHIPPING → REFLECTING → DONE`

Report-only / planning missions use a shorter chain (`ORIENT → RUN → DONE`) and still keep a marker.

## Unit row — boolean exit gates

Every mutating unit (slice, finding, hotspot, dep-group, flake) has one ledger row. Flags are `t`/`f`
(or `n/a` only where noted). A unit is **pipeline-terminal** only when all required flags are `t`
or it is an allowed park class with a human/OPS ref.

| Flag | Means (evidence, not belief) |
|------|------------------------------|
| `BUILD_DONE` | Implementation on the unit branch; build/lint/affected tests green; red-first test present when the unit claims a fix |
| `PR_OPEN` | Integrator opened PR against BASE; `baseRefName==BASE` asserted. **`n/a` only** on the documented no-gh local-merge path (merge-serialization.md) — then `MERGED` still requires ancestry-verified local merge + ledger `no-gh: local-merge` |
| `BOT` | Review-bot wait→ingest→reconcile done, or `n/a` if no bot / bot disabled for the run / no-gh path |
| `REVIEWED` | Build-blind review PASS at `reviewed_sha` (fresh; voided by later push) |
| `MERGED` | Ancestry-verified merge into BASE; merge-commit (not squash); closing SHA in evidence (`oss-contribute`: `f` at `awaiting-maintainer-merge`, `n/a` on assist) |
| `WT_CLEAN` | Unit worktree retired after merge/handoff (dispatch-lifecycle.md guards) |

Canonical row (extend with mission fields, never drop flags):

`| task_id | unit | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | WT_CLEAN | lighting | park | evidence |`

`lighting` is `lit` (default) or `dark-eligible` (gate-classification.md). Omit-or-empty = `lit`.

`park` is empty or a class below. Advance flags only after the verify step; never batch-flip from
memory. The row IS the record: `BUILD_DONE=t` noted only in dispatch logs has not advanced the
unit — RESUME and convergence read row flags, not narration. Flip the flag in the edit that logs the verify.

## Park classes (honest incomplete)

| Class | Meaning | Counts as mission "clean"? |
|-------|---------|----------------------------|
| `needs-human` | One-way / product decision / private state | No — degraded terminal |
| `CODE_CLOSED` | Code merged to BASE; **acceptance cannot be proven** without load/prod data the fleet cannot see | No — degraded; record plan |
| `VERIFY_AT_SCALE` | OPS queue: load test / prod telemetry / live apply still owed | Companion to `CODE_CLOSED` |
| `refuted` / `duplicate` / `externally-resolved` | Not real work for this run | Yes after batch gate where required |
| `out-of-scope` | Wrong mission (hand off) | Not this mission's denominator |
| `awaiting-maintainer-merge` / `externally-covered` | oss-contribute handoffs (upstream-contribution.md): quiet PR (`BUILD_DONE..FOLLOWED_UP,WT_CLEAN=t`, `MERGED=f`; live unparked `MERGED=f` stays in FOLLOW UP) or covered/assist (`BUILD_DONE..MERGED=n/a`, `FOLLOWED_UP,WT_CLEAN=t`); ref=url | Yes — a handoff, not a degradation (mission-chaining.md) |
| `needs-contributor` / `design-disagreement` / `cannot-reproduce` | absorb-it inbound-PR parks: PR needs author action, maintainer decides design dispute, or report did not reproduce on main; ref = PR url + round/repro log | No — degraded terminal (queue not drained while a real contribution sits unanswered) |

`CODE_CLOSED` **requires** a written verify plan (command/checklist) and an OPS/human ref in the
run's OPS actions note under `docs/` (or ledger OPS section). Never use it to skip a runnable test.

## DECISIONS log (durable auto-resolves)

Path: `DECISIONS.md` under the run's REPO_ROOT `docs/` (create if absent). Every mechanical or
taste auto-resolve appends one line with `runtime/scripts/decisions.py append` (refuses malformed lines):

`ts · gate-or-ask-id · class · answer · why · task_id?`

One-way answers that came from a human are logged the same way with `class=one-way` plus
`--source human:<who>` — decisions.py refuses a one-way line without it (and, once
`.orca/human-grant-pubkey` is pinned, without `--grant-sig`). This file is
part of RESUME input — a fresh coordinator re-reads it before re-asking.

## CONTEXT HANDOFF (compaction / shift-change)

On context pressure (degraded recall, lost handles, uncertainty about done flags) — do **not**
push through and do **not** ask the user to "continue." Write a `## CONTEXT HANDOFF` block into
the ledger and state that a fresh coordinator resumes from it:

```
## CONTEXT HANDOFF · <iso-ts>
PHASE: <marker>
BASE: <branch> · FORK_POINT: <sha>
COORDINATOR: <handle(s)>
LIVE: <task_id · dispatchId · handle · branch · PR? · WT id> …
NEXT_WAVE: <ready task ids>
FLAGS_UNMET: <unit → which flags still f>
OPEN_ASKS: <msg ids + default-derived answers already sent>
PARKED: <CODE_CLOSED / needs-human / … with refs>
DECISIONS: path to the DECISIONS log under docs/ (through line …)
```

Then RESUME (liveness-resume.md) applies: scope = header + task ids; git-verify completed units.

## Reflect artifacts (ship / campaign close)

When a mutating mission reaches a terminal state, ensure these exist (create or update under
`docs/`):

- readiness note (what landed on BASE, what's blocked) — shipping-readiness or mission-named
- backlog of noticed-but-not-touched work
- OPS queue (`CODE_CLOSED` / `VERIFY_AT_SCALE` / Lane-0 items)

Report-only missions emit the verdict manifest only.
