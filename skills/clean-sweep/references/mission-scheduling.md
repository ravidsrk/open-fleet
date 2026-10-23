# Runtime policy — scheduled mission runs (Orca automations)

Orca `automations` run a prompt on a schedule (cron / `hourly` / `daily` / `weekdays` / `weekly` /
RRULE) against a fresh per-run worktree or an existing workspace. A scheduled mission is that: an
UNATTENDED coordinator invocation of a mission on a cadence — a nightly `clean-sweep`, a weekday
`review-it` sweep of open PRs.

## Create

```
orca automations create --name "<name>" --trigger daily --time 03:00 --timezone "<IANA zone>" \
  --precheck "<cheap command that exits 0 iff there is work>" \
  --prompt "<the mission invocation, e.g. 'clean-sweep source=tracker on this repo'>" \
  --provider <coordinator agent> --repo id:<repoId> --json
```

`--repo` gives each run a fresh worktree (preferred for missions — clean BASE per run); `--workspace`
targets an existing one. `--disabled` while testing. The provider is the COORDINATOR; workers still
spawn per the roster (sandbox-policy.md).

## `--precheck` is the "is the denominator non-empty?" gate

**Every scheduled mission passes `--precheck`.** It runs a bounded command before the run; exit 0
continues, anything else records a **skipped** run and spawns nothing (`automations.ts:62` at
v1.4.203 — re-witnessed by docs/runs/2026-09-16-pin-it-416/). That is exactly the enumeration question a mission asks in its first phase — and without
it, a nightly sweep of an empty backlog pays a full preflight, a coordinator, and a run report to
discover there was nothing to do, then writes a report that looks like work. The precheck is the
cheapest possible form of the mission's own denominator query. Pass one of these complete shell
commands as the precheck (substitute the label; preserve the inner quotes):

- PRs: `count=$(gh pr list --state open --limit 1 --json number --jq 'length') && test "$count" -gt 0`
- Issues: `count=$(gh issue list --state open --label '<label>' --limit 1 --json number --jq 'length') && test "$count" -gt 0`

Both exit zero only with work. Empty lists and API failures skip; inspect precheck stderr to
distinguish an unavailable denominator from an empty one. Selecting a JSON value alone does not
encode emptiness in the exit status. Keep `&&` so a failed query cannot launch a run.

Also on `create`/`edit`: `--timezone` (a cron with no zone drifts against the team's day),
`--missed-run-grace-minutes` (how late a missed fire may still run — past it the run is dropped, not
silently deferred), `--reuse-session` / `--fresh-session` (existing-workspace automations only;
prefer `--fresh-session` for missions, since a reused session carries the last run's context into a
run whose whole premise is independence), and `--host runtime:<environment-id>` to place the
scheduled coordinator on a paired Orca server rather than the mortal desktop — pass the id from
`orca environment list`, never the environment's name.

`automations run <id>` fires one now (test a schedule without waiting for it); `automations runs
[--id <id>] [--limit <n>] [--cursor <cursor>] [--json]` (`automations.ts:74-103` at v1.4.229) is the paginated run history, and it is the **cross-run anti-inflation input** the fleet currently
reconstructs by hand from `docs/runs/` — a recurring mission reads it to see how many of the last N
fires were `skipped` before believing a streak of green reports.

## A scheduled run is a full run, unattended

- **Autonomy is headless** (gate-classification.md): auto-pick the recommended option on
  mechanical/taste gates; a ONE-WAY gate (freeze, BASE→default promotion, deploy, spend, secret
  rotation) is NEVER faked — the run PARKS it and winds down, surfacing what a human owes. So a
  mission schedules cleanly **iff its value lands BEFORE any one-way gate**: report-only sweeps
  (`review-it`; `attest-it` from a catalog the automation's human author pre-froze at a digest —
  decide-and-freeze's VALIDATE branch, else it parks at FREEZE — the verdict / conformance report is
  the deliverable; a GAP parks to a human) and bounded-source mutation runs that park at their FIRST one-way gate (`clean-sweep` — a
  batch-close gate for a refuted / duplicate item without a recorded grant, else the promotion PR;
  the sweep findings land before either). A scheduled `ship-it` from raw intent parks at the freeze
  gate almost immediately — schedule it only from a pre-frozen spec, and it still stops at PROMOTION_READY.
- **Each run is independent** — its own preflight, BASE, ledger, evidence, and run report. It never
  reuses a prior run's BASE.
- **Cross-run anti-inflation applies** (liveness-resume.md): a recurring run re-reads the prior
  run's completion report and re-verifies its green-but-unverified claims FIRST — a nightly sweep
  must not trust last night's checkmarks. `automations runs --id <id>` is the machine-readable half
  of that history; the run reports are the narrated half, and they are the half that inflates.
- **All safety rails hold** — merge ≠ deploy, one-way doors stay human, least-privilege workers. A
  scheduled run stops at BASE / a report; it never promotes to the default branch.

## Completion

The automation's run output is the mission's normal completion report plus the run's terminal
state and the human-owed queue (parked one-way gates, the promotion PR). At v1.4.229, finished
automation runs sleep their terminal (`terminal sleep`) instead of closing it (`automations.ts:114-130`),
keeping output inspectable without holding a live PTY. A scheduled run that
parked at a gate is a correct outcome, not a failure — the next fire re-enumerates from current
state.

Parked gates have no CLI notification hook: `automations create` carries no notify/mobile flag
(`automations.ts:41-71` at ee1c5220 and HEAD), and attention notifications render desktop-side
with mobile fan-out applied in main (`agent-attention-notification-delivery.ts:1-14`). The run
report plus `automations runs` history is the surface — a parked gate the report buries stays buried.
