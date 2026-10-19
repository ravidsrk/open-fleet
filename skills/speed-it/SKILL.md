---
name: speed-it
description: >-
  Bring declared user journeys within pre-declared performance budgets, proven by measurement.
  Controlled baseline (measure to a metric contract, not once) → profile the real bottleneck → fix
  PR-per-hotspot with a mandatory before/after → re-benchmark to the metric's statistical contract
  → add CI regression guards, looping until every journey is within budget or parked. Use when
  "the app is slow", "perf sweep", "Core Web Vitals", "LCP regression on mobile", "get under
  budget", or an unattended perf-hardening run. Not for a per-diff perf opinion (review-it) or
  post-deploy watch alone (observe via ship-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh. A real MEASUREMENT path
  (Lighthouse/DevTools for web CWV, or a load/profiler harness). A perf worker playbook (addyosmani
  performance-optimization or gstack benchmark) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one budget breach on one frozen critical journey
  state_machine: baseline → diagnose the dominant cause → fix → review → runtime-prove → re-benchmark
  convergence: every frozen journey re-benchmarks inside its declared budget with a CI guard at that budget
  ordering: PR-per-hotspot; the re-benchmark runs after the land, not before
  parking: OPTIMIZED-WITH-PARKED — a breach left names its cause and its gate
  oracle: the declared metric contract measured before→after, not the repo suite
---

# speed-it — every journey within budget, proven by a number

You are the **COORDINATOR**. Unlike a findings mission, here BASELINE MEASUREMENT PRECEDES inventory,
fixes interact systemically, measurements are noisy, and DONE is a STATISTICALLY-DEFINED BUDGET over
journeys — not closure of a finding list. Composes `explain-the-number`, `risk-review` (perf lens), `browser-drive` (the BASELINE
and re-measure capture), `remediate-finding`, `acceptance-review`, `runtime-prove`, `compound-learn`; rides `merge-serialization`,
`reviewed-sha-freshness`, `dispatch-lifecycle`, `liveness-resume`, `evidence-manifest`,
`ledger-contract`, `sandbox-policy`, `attention-budget`. Worker TASK pack: one of addy | gstack — never co-mount.

## Two terminal outcomes

- **WITHIN-BUDGET** — every critical journey meets its budget on its metric contract's confirmation.
- **OPTIMIZED-WITH-PARKED** (degraded) — all fixable hotspots fixed, ≥1 journey over budget needs an
  infra/architecture change beyond scope or is an inherent-cost tradeoff; parked with a human ref.
  Never reported as WITHIN-BUDGET.

## The measurement contract (declare per metric BEFORE baselining)

Two runs is a smoke minimum, not proof. Field CWV = the metric's percentile (p75) over a window +
sample count. Lab CWV = median of ≥5 runs (e.g. 5–10; report spread) at a pinned throttle/cache/device. Server
p95/p99 = the percentile over ≥N requests (e.g. 1k–10k) at stated concurrency, two independent load runs agree.
Baseline and candidate MUST share source, sample size, and pinned conditions — a lab-vs-field or
warm-vs-cold comparison is not a delta. A number you can't measure to its contract is `unmeasured`
(human-flagged), never a downgraded proxy; never fabricate a metric. A number inside its contract
is still `unmeasured` when `explain-the-number` returns inconclusive: no named limiter, an untuned
side, a result past the changed slice's share of the run, errors uncounted, or no proof the timed
work happened.

## Pipeline

```
HUMAN SCOPE CONFIRM: freeze the critical-journey list + per-journey budgets (an unbounded journey
  list is an unbounded mission) → declare metric contracts → BASELINE every journey (to contract,
  and `explain-the-number` is not inconclusive) → rank breaches by gap×traffic
  → DIAGNOSE the bottleneck (profile; symptom→cause tree; name the one dominant cause)
  → BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission speed-it --base <BASE> --fork-point <sha
    recorded in the ledger header at BASE creation>; BASE ≠ default — dispatch-lifecycle.md)
  → FIX PR-per-hotspot (before→after mandatory — the perf form of evidence-manifest.md's negative
    control; GUARD: add a CI budget at the DECLARED budget, not at today's best run) → build-blind REVIEW
    (acceptance-review) → RUNTIME-PROVE (drive the journey at its real entry point — fast but
    behaviorally wrong is a bug, not a win) → LAND
  → RE-BENCHMARK to the contract (a lucky single run is not confirmation). Lab/load contracts
    complete in-mission. Field CWV contracts need the same field source/sample/conditions as baseline
    — that requires deploy; hand off a brief (measurement contract + ship-it release plan) to ship-it
    and do not claim WITHIN-BUDGET on a lab-only delta (OPTIMIZED-WITH-PARKED until field confirms).
  → KEEP-OR-REVERT (the decision table, in precedence order): WORSE than baseline → REVERT —
    even if the number sits within budget; NEUTRAL (inside the noise band) → REVERT — neutral is
    not a keep; IMPROVEMENT over baseline → KEEP, whether or not the budget is reached yet —
    budget attainment gates the journey's exit from the loop, never the keeping of a measured
    gain, so two independent partial fixes accumulate across hotspot PRs. The pipeline's LAND above
    is the merge; a REVERT verdict after a landed PR lands as a follow-up revert PR, never a quiet
    history edit. (Precedence: revert first, keep last.) Every attempt, kept or reverted, is one
    ledger line (hypothesis · before→after · verdict · why) in the run's attempt ledger, so a
    reverted idea is never re-tried next quarter.
  → loop → outcome → REFLECT (`compound-learn`)
```

## Convergence proof

Every journey: within budget confirmed to its metric contract (source, sample, conditions, pasted
numbers) OR parked with a reason. Every fix PR: a measured before→after to its contract, a fresh worker
re-measures a sample. No fabricated metrics (spot-checked). CI budgets added so wins don't rot. A fix
that changes behavior is a bug the review must catch. Manifest names WITHIN-BUDGET or
OPTIMIZED-WITH-PARKED.

## Ledger + supervision

Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (`-` if N/A;
SOURCE = journey-list + metric-contract digests). One row per hotspot (canonical flags per
ledger-contract.md): `| task_id | hotspot | BASELINE | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | BEFORE_AFTER | WT_CLEAN | lighting | park | evidence |` — BEFORE_AFTER = the mandatory
paired measurement, not a narrative.
Stalls → WATCH; death → RESUME scoped to header coordinator + ledger task ids, git-verified.

## Anti-patterns

Optimizing without a baseline (can't prove a win). One fast run = "fixed" (perf is noisy). Confirming
below the metric's contract. Comparing across conditions (lab-vs-field, warm-vs-cold is not a delta).
A GUARD pinned to the post-fix best run (it flakes; guard at the declared budget). A speedup
larger than the removed slice can produce (explain-the-number.md). Scattershot micro-opts instead
of the profiled bottleneck. Unbounded journey list (needs the human-confirmed set).

## Related
`clean-sweep` (general findings), `review-it` (per-diff perf lens), `ship-it` (owns deploy + canary,
and its `observe` phase for post-deploy perf watch when field confirmation is required).
