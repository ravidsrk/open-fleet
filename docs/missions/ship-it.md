# 🚢 ship-it — intent or spec → a released, verified outcome

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — coordinator plus parallel isolated builders and build-blind reviewers; you own the one-way doors (freeze, promotion, deploy).
> **Activation load:** ~33,800 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 17% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** external-run — the 2026-10-13 run built ravidsrk/mdtoc from a maintainer-frozen
> spec to BUILT @ `046d1f8d` on the Linux witness VM (six slices, an integrated FAIL closed by
> a seam-fix slice, re-review PASS); binding report [`docs/runs/2026-10-13-ship-it-mdtoc.md`](../runs/2026-10-13-ship-it-mdtoc.md).
> The earlier [self-run report](../runs/2026-08-28-ship-it-self-run.md) still hashes true at
> `748b328` but never recorded its verifier transcript, so it binds nothing (issue #259).

> Give it an idea or a frozen spec. Come back to a change that is built, reviewed at the
> integrated whole, proven at a real entry point, landed on an integration branch, and taken
> exactly as far down the release state machine as you authorized — with evidence for every claim.

**Skill:** [`skills/ship-it/SKILL.md`](../../skills/ship-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/ship-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/ship-it-light.jpg">
    <img src="../../assets/diagrams/missions/ship-it-light.jpg" alt="Mission contract for ship-it: you give it an intent, or a frozen spec; it interrupts you for gate 1 — confirm the frozen spec; gate 2 — merge the promotion PR; you get back BUILT or PROMOTION_READY or RELEASED or DEPLOYED_AND_VERIFIED, plus slice PRs on BASE; a promotion PR with a traceability table; an evidence manifest per unit; it stops at the highest release state you authorized, suffixed -WITH-PARKED when units were parked with your approval — it never merges to the default branch itself; phases FREEZE, DECOMPOSE, BUILD, REVIEW, PROVE, LAND, RELEASE" width="820">
  </picture>
</p>

---

## Invoke it

```
> ship this: <what to build, or the path to a frozen spec>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: open-fleet RPI runtime (Orca, posix, t3code, ao+). git + gh. One worker playbook pack per worker (mattpocock/skills for grill/tdd, addyosmani for build/verify, gstack for review-army/ship) — never two routers in one worker. Deploy tooling + canary surface for the RELEASED/DEPLOYED states.

## What to provide

- A bounded goal or spec, acceptance criteria and the behavior to preserve.
- The project's baseline test command and the real entry point used to verify the feature.
- The highest authorized stop point: build, promotion PR, release or verified deployment.

## What it does

`ship-it` is the build-to-release fleet. You are not asking one agent to "please implement this" —
you are starting a coordinated run in which a **coordinator** decomposes the work into
tracer-bullet slices, dispatches each slice to a fresh **worker** in its own worktree and terminal,
reviews every slice build-blind, proves the integrated whole at a real entry point, and merges
through a serialized conductor — then walks the release state machine as far as it is allowed.

The coordinator never writes code. Its job is dispatch, verification against authoritative state
(git, the test runner, the deploy target), and keeping the ledger. Every worker emits a SHA-bound
[evidence manifest](../concepts.md#the-evidence-manifest), and an independent verifier checks the
claims before the run advances. A worker saying "done" is a claim to check, never a fact to record.

Two entries, one canonical pipeline:

- **Frozen spec in hand** → the spec is validated (are its dependencies real? are its acceptance
  criteria testable?) and the run goes straight to decomposition.
- **Raw intent** ("build me X") → the coordinator runs a grilling session with *you* — one
  question at a time, recommended answers attached — and freezes the result. The grill is never
  delegated to a worker: it is your side of the alignment conversation.

## When to reach for it

- "Build and ship this feature."
- "Here's the spec — take it to a promotion PR."
- "Spec to shipped product, autonomously; I'll approve the freeze and the merge to main."
- An overnight run where you want to wake up to a reviewed, verified, promotion-ready branch.

**When NOT to reach for it:**

- You have an existing pile of findings or issues to close — that is
  [`clean-sweep`](clean-sweep.md); its unit of work and convergence proof are different.
- The goal is too foggy to write acceptance criteria for — chart it first with
  [`map-it`](map-it.md), then feed the frozen map to `ship-it`.
- You want an opinion, not a change — [`review-it`](review-it.md) produces a verdict with no fix
  authority.

## The pipeline

```mermaid
flowchart TD
    A[Intent or draft] -->|grill + freeze<br/>human gate 1| C[Frozen spec]
    B[Frozen spec handed in] -->|validate| C
    C --> D[DECOMPOSE<br/>tracer-bullet slices → Orca DAG]
    D --> E[BUILD waves<br/>one worker per slice, failing test first]
    E --> F[ACCEPTANCE-REVIEW<br/>build-blind, per slice]
    F --> G[RUNTIME-PROVE<br/>drive the real entry point]
    G --> H[LAND<br/>merge conductor, one train]
    H --> H2[INTEGRATED PROVE at the BASE head<br/>traceability table verified over the whole]
    H2 --> I{{BUILT}}
    I --> J[PROMOTION PR<br/>traceability table]
    J --> K{{PROMOTION_READY}}
    K -->|human merges<br/>human gate 2| L{{RELEASED}}
    L -->|deploy + canary window| M{{DEPLOYED_AND_VERIFIED}}
```

Phase by phase:

1. **Freeze** ([`decide-and-freeze`](../../playbooks/decide-and-freeze.md)). Facts are looked up
   in the codebase; decisions go to you. The output is a spec with testable acceptance criteria,
   explicit non-goals, and a test-seam list — sketched *before* the spec, not retrofitted after.
   Frozen scope does not reopen; new wants become backlog entries.
2. **Decompose** ([`decompose-dag`](../../playbooks/decompose-dag.md)). The spec is cut into
   vertical slices — each a narrow but complete path through every layer it touches, demoable
   alone, sized for one fresh context window. Foundation work (scaffold, data layer, seams)
   serializes; slices parallelize behind it. Hot mount-point files (route registries, DI wiring,
   migrations) become merge chains so parallel workers never fight over them.
3. **Build** ([`build-change`](../../playbooks/build-change.md)). Every worker starts from a clean
   baseline and writes the failing test first, with the expected value derived from an independent
   source of truth — never recomputed the way the code computes it. Smallest change to green.
   Adjacent problems are noticed-but-not-touched: recorded to the backlog, not fixed on the sly.
4. **Review** ([`acceptance-review`](../../playbooks/acceptance-review.md)). A fresh session that
   did not write the code reviews each slice on isolated axes — standards, spec fidelity,
   test adequacy — with no cross-axis reranking. Findings must quote the motivating line or they
   drop to an appendix. Two disciplines keep it honest: the reviewer writes its own expected fix
   to disk *before* opening the diff (anti-anchoring), and a unit gets at most three failed
   review rounds before it parks with a gate instead of ping-ponging forever.
5. **Prove** ([`runtime-prove`](../../playbooks/runtime-prove.md)). Green units are the start of
   verification, not the end. The change is driven through its true public entry point and the
   persisted state is asserted — plus a negative control: revert the change, watch the proof go
   red, restore it. It runs per slice before landing, and again over the **integrated whole** at
   the BASE head once the wave lands — the traceability table is verified there, never inferred
   from per-slice green.
6. **Land** ([`merge-serialization`](../../runtime/merge-serialization.md)). One conductor owns
   all merges to the integration BASE. Reviewed-SHA freshness is enforced: a rebase voids the
   review and the PR re-boards with a fresh one.
7. **Release** ([`release`](../../playbooks/release.md)) and **observe**
   ([`observe`](../../playbooks/observe.md)). Version bump, changelog, promotion PR with a
   traceability table; a human merges to the default branch; deploy and a canary window follow
   only where authorized.

## Terminal states

*Stop where your authorization ends.*

| State | Meaning | Who acts on it |
|---|---|---|
| `BUILT` | Every slice merged to BASE, ancestry-verified | the fleet |
| `PROMOTION_READY` | Promotion PR open with a traceability table | a human, always |
| `RELEASED` | Human merged the promotion PR to the default branch | ops / authorization |
| `DEPLOYED_AND_VERIFIED` | Deployed revision equals the released SHA, canary green over its window | terminal |
| `BUILT-WITH-PARKED` (or any higher state, suffixed) | units or criteria parked with human-approved reasons while the rest landed; allowed parks are `needs-human`, `CODE_CLOSED` + `VERIFY_AT_SCALE` with a plan, or a human-authorized scope exclusion | a human clears each named park |

The mission **names the state it reached** and what blocks the next one. Reaching BASE with an
open promotion PR is `PROMOTION_READY` — reporting it as `RELEASED` is the overclaim this state
machine exists to prevent.

A **solo run** — no second GitHub identity to review the work — cannot close a mutation unit: it
records RED and stops at `BUILT`, or takes the executed-control lane; it never self-approves.
`BUILT-WITH-PARKED` is a degraded terminal; it is never reported as `BUILT`.

## Human gates

Two in every run, both one-way doors under
[`gate-classification`](../../runtime/gate-classification.md):

1. **The freeze** (intent entry only) — you confirm the spec before any slice is cut.
2. **The promotion** — merging BASE to the default branch is always yours. The fleet opens the
   PR with the traceability table and an `accountable: <human>` line, then stops. Merge ≠ deploy,
   and the fleet never self-merges a promotion.

Past `RELEASED`, deploy and rollback are one-way doors as well: the fleet executes a deploy only
under a recorded human grant, and the canary loop surfaces a rollback option rather than taking it.

Everything else is classified mechanical (auto-resolved, audited in the ledger) or taste
(recommendation picked, batched for your veto, work continues).

## Convergence proof

`ship-it` is done when — and only when — the verifier confirms, against authoritative state:

- every frozen acceptance criterion maps to a passing test in a traceability table, verified on
  the **BASE head** (the integrated whole, not per-slice green);
- the criterion set is re-derived from the frozen spec at its recorded digest, so no worker can
  quietly shrink the denominator;
- every slice has a merged, ancestry-verified PR, a fresh reviewed SHA, and a passing negative
  control (revert-audited on a sample by a fresh worker);
- the manifest names the terminal release state with its evidence — merge SHA, deploy revision,
  canary verdict;
- everything noticed but not touched is in a backlog file.

## A worked example

The ask: passwordless login for a Next.js + Postgres app.

> ship this: magic-link login — email a signed link, 15-minute expiry, reuse the existing
> session middleware

**Freeze (gate 1).** The coordinator grills you, one question at a time, recommendation attached:

> Token storage — (a) stateless signed JWT in the link (recommended: no schema change; revocation
> only by expiry) or (b) DB-backed one-time token (revocable, adds a table + cleanup)?

You pick (b) — support wants revocation. The frozen spec carries five acceptance criteria
(AC-1 request endpoint … AC-5 rate limit) and two non-goals (no SSO, no account merge).

**Decompose → build.** The token table + mailer seam is foundation and serializes; three slices
build in parallel behind it, each from a failing test. Mid-build, one ledger row reads:

```
| task_a41 | AC-3 verify+session | BUILD_DONE t | PR_OPEN t | BOT t | REVIEWED f | MERGED f | WT_CLEAN f |  | PR #214 @ 9c1f2e0 |
```

**Review → prove → land.** The build-blind reviewer fails AC-3 once (missing expired-token
case); one fix round passes. RUNTIME-PROVE drives the real flow — request a link against the
dev server, extract it from the mail sink, verify, assert the session cookie — and files the
transcript as an artifact. The conductor merges the train; every row ends `MERGED t · WT_CLEAN t`.

**Promotion (gate 2).** The fleet opens the promotion PR with its traceability table (AC ↔ PR ↔
test ↔ merge SHA) and stops at `PROMOTION_READY`. Merging to `main` is your click, not its.

## Failure modes this mission is built to prevent

| Anti-pattern                       | Why it burns you                                                      |
|------------------------------------|-----------------------------------------------------------------------|
| Fanning the grill to a worker      | The alignment conversation is with *you*; a worker answering your side is fiction |
| Building on a moving spec          | Reviews and acceptance tests lose their fixed point; freeze first     |
| Per-slice green mistaken for done  | Slices can pass alone and fail integrated; runtime-prove the whole    |
| Claiming RELEASED at an open PR    | The release state machine exists so nobody has to trust adjectives    |
| Two playbook routers in one worker | Upstream packs fight when co-mounted; one worker, one pack            |

## Composes
At activation — the SKILL's Composes/rides clause, what a coordinator loads before the first dispatch:

Playbooks:
[`decide-and-freeze`](../../playbooks/decide-and-freeze.md) ·
[`decompose-dag`](../../playbooks/decompose-dag.md) ·
[`build-change`](../../playbooks/build-change.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`runtime-prove`](../../playbooks/runtime-prove.md) ·
[`linear-enumeration`](../../playbooks/linear-enumeration.md)

Runtime policies:
[`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md) ·
[`merge-serialization`](../../runtime/merge-serialization.md) ·
[`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md) ·
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`gate-classification`](../../runtime/gate-classification.md) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) ·
[`attention-budget`](../../runtime/attention-budget.md) ·
`orca-dag-semantics` (phase-cued: read when composing the DAG, not standing load)

Deferred reads, loaded on entering their phase and never at activation: [`liveness-resume`](../../runtime/liveness-resume.md) when a worker stalls or a run resumes · [`plan-review`](../../playbooks/plan-review.md) on the map-it handoff route · [`risk-review`](../../playbooks/risk-review.md) when a slice's surface triggers a lens · [`release`](../../playbooks/release.md) at RELEASE · [`observe`](../../playbooks/observe.md) at DEPLOYED_AND_VERIFIED · [`human-handoff`](../../playbooks/human-handoff.md) at a handoff · [`completion-audit`](../../playbooks/completion-audit.md) + [`compound-learn`](../../playbooks/compound-learn.md) at run close · [`mission-chaining`](../../runtime/mission-chaining.md) as a chain link.

## Related missions

- [`map-it`](map-it.md) — chart a foggy goal into the frozen spec this mission consumes.
- [`clean-sweep`](clean-sweep.md) — close an existing set of findings instead of building new work.
- [`review-it`](review-it.md) — the verdict without the build.
