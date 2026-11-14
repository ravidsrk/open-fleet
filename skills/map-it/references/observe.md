# Playbook — observe  (post-release canary monitoring)

Recipe: gstack `canary`. The monitoring LOOP runs after a deploy (inside release.md's
DEPLOYED_AND_VERIFIED phase, following its deploy step), never
inside a generic verify — but step 1's baseline is captured immediately BEFORE the deploy (the
calling mission must sequence it there; ship-it does). Observe-and-report by default; rollback is a
human gate.

## Loop

1. `--baseline` BEFORE deploy: per-page screenshot + console errors + load time saved.
2. After deploy, loop every ~60s for a duration: goto / snapshot / console --errors / perf.
3. **Alert on CHANGE vs baseline, not absolutes:** 3 baseline errors is fine if still 3; one NEW
   error alerts. Perf regression = >2× baseline. Only fire on a pattern persisting 2+ CONSECUTIVE
   checks (don't cry wolf). Severity CRITICAL (page fail) / HIGH (new console errors) / MEDIUM (>2×
   load) / LOW (new 404). Screenshot attached to every alert as evidence.
4. On CRITICAL/HIGH → surface to the human with the rollback option; never auto-rollback.

## Depth scales with the change surface

docs = skip · config = smoke (200s) · backend = console + perf · frontend = full + screenshot.

## Teardown is observed too

A post-deploy branch delete (or any cleanup the deploy step triggers) is RECONCILED, not assumed:
read the branch back and record deleted / still-present / unknown. A delete whose outcome cannot be
verified is REPORTED as unverified, never counted as clean — an assumed-clean teardown is how a
stale branch survives into the next run's enumeration.

## Completion

A health report (baseline vs observed, per page, with screenshots) over the full window; every alert
has 2-consecutive confirmation + evidence; rollback decisions are human. A first-check-only "green"
is not an observation.
