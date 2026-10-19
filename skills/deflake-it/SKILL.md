---
name: deflake-it
description: >-
  Eliminate intermittent test failures to a declared confidence contract. Detect flakes by repeat-
  run + CI retry history, diagnose each with a loop that RAISES the failure rate (never a theory),
  fix the root cause and ratchet it red-by-revert, then re-run the whole suite for a consecutive
  green streak — local AND in CI — looping until the streak holds. Retry-wrappers as fixes are
  banned and grep-checked. Use when "kill the flaky tests", "deflake the CI", "flake zero", a
  flaky/intermittent suite. Not for a single hard bug with no suite-rate contract (root-cause) or
  deterministic failures (clean-sweep).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; a runnable suite. A
  feedback-loop-first debugging playbook (mattpocock diagnosing-bugs or addyosmani debug) — one router
  per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one intermittent failure distribution — a rate, not a defect
  state_machine: detect by repeat-run → RAISE the failure rate → fix the cause → ratchet red-by-revert → streak
  convergence: the whole suite holds a consecutive green streak to the declared confidence contract, local AND in CI
  ordering: the suite-wide streak re-runs after every landed fix
  parking: STABLE-WITH-QUARANTINE — quarantine is named; retry-wrappers as fixes are banned and grep-checked
  oracle: the measured repeat-run failure rate — a loop that raises it, never a theory
---

# deflake-it — green N times in a row, local and CI

You are the **COORDINATOR**. The unit is an INTERMITTENT FAILURE DISTRIBUTION, not a defect: detection
and proof require REPEATED observations, environment correlation, and a consecutive-green / statistical
contract. Rerun behavior IS the mission, not verification-after-a-fix. Composes `diagnose`,
`build-change`, `remediate-finding` (the finding is a flake; the red-by-revert ratchet is its
negative control), `acceptance-review`, `compound-learn`; rides `merge-serialization`,
`reviewed-sha-freshness`, `dispatch-lifecycle`, `liveness-resume`, `evidence-manifest`,
`ledger-contract`, `sandbox-policy`, `attention-budget`. The suite green streak IS the prove step (no separate
runtime-prove pass). Worker TASK pack: one of matt | addy — never co-mount.

## Two terminal outcomes

- **STABLE** — the full suite passes `GREEN_STREAK` consecutive runs, local AND CI, with zero
  flakes and zero retry-wrappers. The streak is a PRE-DECLARED statistical contract, not a vibe:
  N green runs bound the residual per-run flake rate at p ≤ 1 − 0.05^(1/N) with 95% confidence
  (N=10 only proves p ≲ 26%; N=30 → p ≲ 9.5%; N=100 → p ≲ 3%; catching a 1% flake needs ~300).
  The bound assumes INDEPENDENT runs — correlated flakes (shared state, time-of-day, load) violate
  it, so vary seed/order/parallelism/time across the streak and treat the bound as optimistic.
  Default: declare target residual rate, derive N (default GREEN_STREAK=30 if unspecified). Record
  both target rate and N in the manifest's `metric_contract`.
- **STABLE-WITH-QUARANTINE** (degraded) — ≥1 flake survives diagnosis with no root cause and is
  quarantined with a human-approved tracking ticket. Never reported as STABLE.

## Pipeline

```
DETECT: run the suite DETECT_RUNS times (default 30; varied seed/order; parallel only at the target
  env's concurrency — self-parallel copies colliding on ports/tmp/DB measure a different distribution,
  so record the run conditions with the rate) → per-test flake RATE;
  mine CI retry history (pass-on-retry tests flake in an env local runs don't reproduce — capture even
  at local rate 0). Deterministic N/N failures are BUGS → route to clean-sweep, out of scope.
  → DIAGNOSE (diagnose playbook, adapted): build a loop that RAISES the failure rate (tight loop, under
    load, clock skew, shuffled order, shared-state siblings); classify the taxonomy (order-dependence /
    shared mutable state / real time-or-tz / network / unseeded RNG / resource leak / too-tight timeout
    / async race) → the class dictates the fix.
  → BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission deflake-it --base <BASE> --fork-point <sha
    recorded in the ledger header at BASE creation>; BASE ≠ default — dispatch-lifecycle.md)
  → FIX root cause + RATCHET red-by-revert (revert only the fix, show the flake returns at its measured
    rate; restore, show it's gone across a mini-streak) — never `retry(3)` a flake into hiding.
  → close per remediate-finding: PR-per-flake against BASE → build-blind REVIEW (acceptance-review)
    → conductor LAND
  → PROVE: full suite GREEN_STREAK consecutive runs, local AND verified in CI (gh run list), all at
    ONE SHA — the BASE head after the last fix lands; a new commit restarts the streak. Trigger CI
    re-runs with `gh run rerun` / `gh workflow run`, never empty commits. ANY flake resets the
    streak to zero and re-enters detection. → loop → outcome → REFLECT (`compound-learn`)
```

## Convergence proof

Every detected flake (local AND CI-only) reaches a terminal state: root-caused + fixed + merged (with a
red-by-revert ratchet) OR quarantined with a human-approved ticket — no "documented and left flaky"
exit. CI-only flakes: the local streak does NOT disprove them; each fixed-and-verified-in-CI (green
across the same resolved_N consecutive CI triggers, `gh run list` pasted) or quarantined. The streak (timestamps +
seeds/orders per run) pasted, local AND CI. Zero retry/rerun wrappers added (grep the diff).
Manifest names STABLE or STABLE-WITH-QUARANTINE.

## Ledger + supervision

Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (`-` if N/A;
SOURCE = DETECT_RUNS · GREEN_STREAK=resolved_N · target residual rate). One row per flake (canonical
flags per ledger-contract.md): `| task_id | flake | RATE_RAISED | ROOT_CAUSE | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | RED_BY_REVERT | WT_CLEAN | lighting | park | evidence |` —
RESUME reads flags, not prose.
Stalls → WATCH; death → RESUME scoped to header coordinator + ledger task ids, git-verified.

## Anti-patterns

Theorizing before a loop that reproduces at elevated rate. `retry(n)` / `--rerun-failures` as the fix
(hides flakes, poisons the signal). One green run = done. Treating an N/N deterministic failure as a
flake (it's a bug — clean-sweep). Widening a timeout that masks a real race. Deleting or skipping a
flaky test (a quarantine with a human-approved ticket is the only exit). A streak stitched across
commits (it proves nothing about the head).

## Related
`root-cause` (a single hard intermittent bug, not a suite-rate contract), `prove-it` (coverage),
`clean-sweep` (deterministic bugs).
