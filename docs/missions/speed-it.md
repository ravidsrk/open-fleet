# ⚡ speed-it — every journey within budget, proven by a number

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel hotspot workers under a pre-declared measurement contract; you own the one-way doors.
> **Activation load:** ~31,000 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 16% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** doctrine-only — no recorded run yet; the protocol is mechanism, not yet field-proven.

> Declare the journeys and their budgets. Come back to every one of them measured within budget
> against a pre-declared statistical contract — a before/after on every fix, a CI regression
> guard so the wins don't rot, and not a single number you have to take on faith.

**Skill:** [`skills/speed-it/SKILL.md`](../../skills/speed-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/speed-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/speed-it-light.jpg">
    <img src="../../assets/diagrams/missions/speed-it-light.jpg" alt="Mission contract for speed-it: you give it the journeys and their budgets; it interrupts you for a metric that cannot be measured to its contract; parking a journey; promotion; you get back WITHIN-BUDGET or OPTIMIZED-WITH-PARKED, plus before, after on every fix PR; CI regression guards; a re-benchmark to the contract; it stops at never a weaker proxy metric, never a lucky single run; phases DECLARE, BASELINE, RANK, DIAGNOSE, FIX, PROVE, RE-BENCHMARK" width="820">
  </picture>
</p>

---

## Invoke it

```
> the app is slow — journeys: <list them>; budgets: <the targets>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh. A real MEASUREMENT path (Lighthouse/DevTools for web CWV, or a load/profiler harness). A perf worker playbook (addyosmani performance-optimization or gstack benchmark) — one router per worker.

## What to provide

- The user journeys, metrics and numeric budgets you want to meet.
- A measurement harness, environment and representative dataset.
- The owner who freezes measurement conditions and decides infrastructure or architecture tradeoffs.

## What it does

`speed-it` is the performance-budget fleet, and it is deliberately not a findings mission. Here
**baseline measurement precedes inventory** — you cannot rank what you have not measured — fixes
interact systemically, measurements are noisy, and done is a **statistically-defined budget over
journeys**, not the closure of a list. A **coordinator** declares metric contracts, baselines
every journey, ranks the breaches, dispatches one fix PR per profiled hotspot, and re-benchmarks
the journeys until every one is within budget or parked with a human reference.

The spine of the mission is the **measurement contract**, declared per metric before any number
is taken:

- **Field Core Web Vitals** — the metric's percentile (p75) over a window, with the sample count.
- **Lab Core Web Vitals** — the median of ≥5 runs, spread reported, at a pinned throttle, cache
  state, and device.
- **Server latency** — p95/p99 over ≥N requests at a stated concurrency, with two independent
  load runs agreeing.

Baseline and candidate must share source, sample size, and pinned conditions — a lab-vs-field or
warm-vs-cold comparison is not a delta, and two runs is a smoke minimum, not proof. A number that
cannot be measured to its contract is `unmeasured` and human-flagged, never a downgraded proxy.
So is a number [`explain-the-number`](../../playbooks/explain-the-number.md) calls inconclusive:
no named limiter, an untuned side, a result past the changed slice's share of the run, errors
uncounted, or no proof the timed work happened.
And a metric is **never fabricated** — every pasted number is spot-checked against the artifacts
in its [evidence manifest](../concepts.md#the-evidence-manifest).

## When to reach for it

- "The app is slow."
- "Get these journeys under budget." / "Core Web Vitals are failing."
- A perf sweep before a launch, or an unattended perf-hardening run.

**When NOT to reach for it:**

- A per-diff perf opinion on one change — that is [`review-it`](review-it.md) running the
  [`risk-review`](../../playbooks/risk-review.md) performance lens.
- A general findings backlog — [`clean-sweep`](clean-sweep.md); its proof is an empty list, not
  a met budget.
- Watching production after a release — that is the [`observe`](../../playbooks/observe.md)
  playbook inside a release run, not a campaign.

## The pipeline

```mermaid
flowchart TD
    A[Journeys + budgets declared] --> B[DECLARE metric contracts<br/>per metric, before any number]
    B --> C[BASELINE every journey<br/>measured to its contract]
    C --> D[RANK breaches<br/>gap × traffic]
    D --> E[DIAGNOSE<br/>profile, name the one dominant cause]
    E --> F[FIX PR-per-hotspot<br/>before/after + CI GUARD]
    F --> G[REVIEW + RUNTIME-PROVE<br/>drive the journey end to end]
    G --> H[LAND<br/>merge conductor, one train]
    H --> I[RE-BENCHMARK<br/>to the contract]
    I -->|breaches remain| D
    I -->|every journey in budget| J{{WITHIN-BUDGET}}
    I -->|only parked breaches remain| K{{OPTIMIZED-WITH-PARKED}}
```

Phase by phase:

1. **Declare contracts.** Per metric, before baselining — the contract is what makes a later
   "improved" claim falsifiable instead of vibes.
2. **Baseline.** Every declared journey is measured to its contract *before* any inventory of
   fixes exists. Optimizing without a baseline is the cardinal sin: with no starting number, no
   fix can ever prove a win.
3. **Rank.** Breaches are ordered by **gap × traffic** — how far over budget, times how many
   users feel it — so the fleet spends effort where the user-felt win is largest.
4. **Diagnose** ([`risk-review`](../../playbooks/risk-review.md), performance lens). Profile,
   walk the symptom→cause tree (slow load: bundle, or TTFB?), and name the **one dominant
   cause**. Scattershot micro-optimizations are a named anti-pattern, not a strategy.
5. **Fix, one PR per hotspot** ([`remediate-finding`](../../playbooks/remediate-finding.md)).
   Every fix PR carries a mandatory measured **before → after** to its metric contract, and adds
   a **CI regression budget** (GUARD) so the win cannot silently rot after the run ends.
6. **Review and prove** ([`runtime-prove`](../../playbooks/runtime-prove.md)). A build-blind
   review, then the journey is driven at its real entry point — fast but behaviorally wrong is a
   bug, not a win, and the review must catch it.
7. **Land and re-benchmark** ([`merge-serialization`](../../runtime/merge-serialization.md)).
   The conductor merges; then the journey is re-measured to its full contract — a lucky single
   run is not confirmation. Because fixes interact systemically, the loop re-ranks whatever is
   still breached and goes again.

## Terminal states

*Name the one reached.*

| State | Meaning | Who acts on it |
|---|---|---|
| `WITHIN-BUDGET` | Every critical journey meets its budget on its metric contract's confirmation | terminal |
| `OPTIMIZED-WITH-PARKED` | All fixable hotspots fixed; ≥1 journey needs an infra/architecture change beyond scope or is an inherent-cost tradeoff — parked with a human ref | a human decides the tradeoff |

`OPTIMIZED-WITH-PARKED` is a degraded outcome, never a synonym — reporting it as `WITHIN-BUDGET`
is exactly the overclaim the measurement contract exists to prevent.

## Human gates

- **`unmeasured` metrics.** A metric that cannot be measured to its declared contract is flagged
  to you — the fleet never quietly substitutes a weaker proxy.
- **Parking a journey.** An over-budget journey parks only with a human reference — an infra or
  architecture change beyond scope, or an accepted inherent-cost tradeoff.
- **Promotion.** As everywhere, merging BASE to the default branch is a one-way human gate; the
  fleet stops at the promotion PR.

## Convergence proof

`speed-it` is done when — and only when:

- every declared journey is within budget, **confirmed to its metric contract** — source,
  sample, conditions, and the numbers pasted — or parked with its reason;
- every fix PR carries a measured before → after to its contract, and a fresh worker has
  re-measured a sample of them;
- no metric is fabricated — pasted numbers are spot-checked against their artifacts;
- CI budgets are in place, so the wins are guarded after the run ends;
- no fix changed behavior — fast-but-wrong is a bug the review must catch, not a win.

## A worked example

The ask: checkout feels slow. Budget: p95 ≤ 2.5s for the three declared journeys.

**Declare before measuring.** Per metric, a contract: p95 over 30 scripted runs, cold cache,
4× CPU throttle, the staging data snapshot, run-to-run variance recorded. No number exists
before its contract does — that is what makes "fixed it" falsifiable later.

**Baseline → rank.** Browse and search sit inside budget; checkout breaches at p95 3.8s.
Ranked by gap × traffic, checkout is the only hotspot worth a wave.

**Diagnose to ONE dominant cause.** The profile shows 42 near-identical queries per checkout —
an N+1 on cart items — dwarfing everything else. The worker names that single cause in the
ledger; a fix PR that cannot name its cause does not open.

**Fix + guard.** A batched loader takes the journey from 3.8s → 2.1s, measured to the same
contract, before/after in the PR body. The same PR adds the CI guard: a query-count assertion
(≤ 3 per checkout) that turns a regression into a red build instead of a slow quarter.

**Re-benchmark → terminal.** All three journeys measure inside budget: **WITHIN-BUDGET**. The
counter-case is worth knowing: had image weight on browse breached with the fix being a CDN
migration, that journey would park with a human reference and the run would end
`OPTIMIZED-WITH-PARKED` — parked with a name, never quietly dropped.

## Failure modes this mission is built to prevent

| Anti-pattern                                  | Why it burns you                                                |
|-----------------------------------------------|-----------------------------------------------------------------|
| Optimizing without a baseline                 | With no starting number, no fix can ever prove a win            |
| One fast run declared "fixed"                 | Perf is noisy; the contract's statistics are the confirmation   |
| Comparing across conditions                   | Lab-vs-field or warm-vs-cold is not a delta                     |
| Confirming below the metric's contract        | Two runs is a smoke minimum, not proof                          |
| Scattershot micro-optimizations               | Profile first; fix the one dominant cause                       |
| Downgrading an unmeasurable metric to a proxy | It is `unmeasured` and human-flagged — never an invented number |

## Composes
Playbooks:
[`explain-the-number`](../../playbooks/explain-the-number.md) ·
[`risk-review`](../../playbooks/risk-review.md) (performance lens) ·
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`runtime-prove`](../../playbooks/runtime-prove.md) ·
[`compound-learn`](../../playbooks/compound-learn.md) ·
[`browser-drive`](../../playbooks/browser-drive.md)

Runtime policies:
[`merge-serialization`](../../runtime/merge-serialization.md) ·
[`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md) ·
[`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md) ·
[`liveness-resume`](../../runtime/liveness-resume.md) ·
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) ·
[`attention-budget`](../../runtime/attention-budget.md)

## Related missions

- [`clean-sweep`](clean-sweep.md) — general findings; done is an empty list, not a met budget.
- [`harden-it`](harden-it.md) — the security campaign; done is a clean re-audit.
- [`review-it`](review-it.md) — the per-diff perf lens without the campaign loop.
