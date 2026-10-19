# 🧪 prove-it — a mutation-audited test on every critical path

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel characterize and mutate workers per critical path; you own the one-way doors.
> **Activation load:** ~29,500 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 15% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** self-run — [2026-09-16 run](../runs/2026-09-16-prove-it-self-run.md) (PF-2 kind gate, COVERED, 4/4 mutants killed).

> Point it at the money, auth, and data paths nothing currently protects. Come back to a
> human-confirmed critical surface where every path has a merged test that dies under a
> behavior-changing mutation — and every bug the tests surfaced was fixed, parked, or handed
> off, never quietly asserted as correct.

**Skill:** [`skills/prove-it/SKILL.md`](../../skills/prove-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes — tests, plus small clear fixes for surfaced bugs

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/prove-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/prove-it-light.jpg">
    <img src="../../assets/diagrams/missions/prove-it-light.jpg" alt="Mission contract for prove-it: you give it a runnable suite and a coverage tool; it interrupts you for confirming the critical surface; behaviour calls on bugs the tests surface; you get back COVERED or COVERED-WITH-PARKED, plus merged tests that die under mutation; surfaced bugs fixed, parked, or handed off; it stops at never asserting buggy behaviour as correct; phases MAP, CONFIRM, CHARACTERIZE, MUTATION-AUDIT, REVIEW, LAND, RE-MAP" width="820">
  </picture>
</p>

---

## Invoke it

```
> close the test gap on <the money, auth and data paths>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; a runnable suite + coverage tool. A TDD worker playbook (addyosmani or mattpocock) — one router per worker.

## What to provide

- The critical behavior paths, existing tests and available coverage information.
- A runnable suite and mutation tooling, or the hand-mutant fallback.
- The person who confirms the critical-path scope and owns bugs exposed by the audit.

## What it does

`prove-it` is the test-debt fleet. Unlike a finding-driven mission, the work here **creates
proof where no defect finding necessarily exists**: a **coordinator** maps the untested critical
surface, a human confirms the scope, and **characterization workers** — each running a single
TDD playbook (addyosmani or mattpocock) as its router — write tests that assert what the code
really does, then prove each test earns its keep. Every unit emits a SHA-bound
[evidence manifest](../concepts.md#the-evidence-manifest).

The denominator is a **finite critical surface**: coverage gaps crossed with the call-graph of
the money, auth, data, and external-contract entry points. Uncovered trivial getters are not
the mission, and coverage percent is not the pass criterion — 100% with tautological asserts
proves nothing. Done is **mutation-sensitive** coverage of the confirmed surface.

The proof itself is the heart of the mission: a test counts only if a **behavior-changing, harness-preserving
mutation** of the code — one that still compiles, under a harness that still runs — makes the
targeted assertion fail. (A mutation that preserved semantics would be an equivalent mutant —
unkillable by any test — which is exactly what the audit must not count.) And when characterization reveals the code is wrong, a nested
remediation loop takes over: the buggy behavior is never asserted as correct.

## When to reach for it

- "Close the test gap." / "Cover the critical paths."
- Test debt on code you are about to refactor — characterize first with prove-it's net, then
  restructure with [`reshape-it`](reshape-it.md) (its DEEPEN units require that net to exist).
- The suite is green but you have no idea whether it would catch a real regression.
- An audit demands proof the money/auth/data paths are tested, not a coverage number.

**When NOT to reach for it:**

- The suite is intermittently red — a flaky harness cannot anchor a mutation audit; run
  [`deflake-it`](deflake-it.md) first.
- You already have a pile of known bugs to close — that is [`clean-sweep`](clean-sweep.md).
- The tests are for new work — [`ship-it`](ship-it.md) builds them in, failing test first.
- The net exists and the goal is restructuring the module it covers — [`reshape-it`](reshape-it.md)
  (its DEEPEN units consume this mission's characterization net).

## The pipeline

```mermaid
flowchart TD
    A[Runnable suite + coverage tool] --> B[MAP critical surface<br/>coverage gaps × call-graph of<br/>money/auth/data/external-contract paths]
    B --> C[HUMAN scope confirm<br/>bounds the mission]
    C --> D[CHARACTERIZE waves<br/>assert the real behavior]
    D --> E{"Test passes, or<br/>reveals a bug?"}
    E -->|passes| F[MUTATION AUDIT<br/>flip a boundary, negate a condition —<br/>the targeted assertion must fail]
    E -->|bug| G[SURFACED-BUG sub-loop<br/>fix in-PR, park, or hand to clean-sweep]
    F --> H[Build-blind REVIEW]
    G --> H
    H --> I[RUNTIME-PROVE<br/>the asserted behavior is real<br/>at the true entry point]
    I --> J[LAND<br/>merge conductor]
    J --> K[RE-MAP coverage]
    K -->|paths remain| D
    K -->|surface exhausted, nothing parked| L{{COVERED}}
    K -->|surface exhausted, parked items| M{{COVERED-WITH-PARKED}}
```

Phase by phase:

1. **Map.** Coverage gaps are crossed with the call-graph of the money, auth, data, and
   external-contract entry points to produce a finite list of untested critical paths. This is
   the mission's denominator; without it, nothing can converge.
2. **Confirm scope.** A human confirms the critical list before any test is written. The
   confirmation bounds the mission — an unbounded surface is the anti-pattern, not a bigger
   win.
3. **Characterize** ([`build-change`](../../playbooks/build-change.md)). Each worker writes a
   characterization test that asserts **real** expected behavior, with the expected value drawn
   from an independent source of truth — never recomputed the way the code computes it (the
   tautology guard). Two outcomes: the test passes, meaning the code was correct but untested;
   or the test reveals a bug.
4. **Mutation-audit** the passing test. Apply a behavior-changing, harness-preserving mutation — flip a
   boundary, negate a condition, zero a return — so the code still **compiles** and the harness
   still **runs**, and watch the targeted assertion fail. A mutation that breaks the compile or
   the imports proves the test depends on the source's shape, not its behavior — it does not
   count.
5. **Surfaced-bug sub-loop** ([`remediate-finding`](../../playbooks/remediate-finding.md)). A
   small, clear fix ships in-PR with its test. Anything ambiguous or behavior-changing is
   parked as needs-human or handed to [`clean-sweep`](clean-sweep.md). The one forbidden move
   is asserting the buggy behavior as correct — that freezes the defect into the contract.
6. **Review, prove, land, re-map** ([`runtime-prove`](../../playbooks/runtime-prove.md),
   [`merge-serialization`](../../runtime/merge-serialization.md)). A build-blind review checks
   each test; runtime-prove confirms the characterization asserts behavior the real entry point
   actually exhibits, not behavior the test harness fabricates; the conductor lands; coverage
   is re-mapped and the loop continues until the confirmed surface is exhausted.

## Terminal states

*Parked is not covered.*

| State | Meaning | Who acts on it |
|---|---|---|
| `COVERED` | Every confirmed path has a merged, mutation-audited test; every surfaced bug fixed-with-test | terminal — the promotion PR is yours |
| `COVERED-WITH-PARKED` | All writable paths mutation-audited; at least one bug or path parked as needs-human | a human decides each parked path or bug |

The degraded state is never reported as `COVERED`. A parked item names its blocker — a
load-bearing quirk, a behavior-change decision, a path untestable without a human call.

## Human gates

Per [`gate-classification`](../../runtime/gate-classification.md):

1. **The scope confirm.** You approve the critical surface before characterization begins. This
   is what makes the denominator finite and the convergence proof checkable.
2. **The behavior call.** When a characterization test reveals what might be a load-bearing
   quirk — or a fix that would change observable behavior — the decision is yours; the worker
   parks it as needs-human rather than guessing.

Fix-backed closes need no extra gate: the evidence chain is the authorization.

## Convergence proof

`prove-it` is done when — and only when:

- every path on the confirmed critical surface has a merged test that fails at its assertion
  under a behavior-changing, harness-preserving mutation, with the harness still runnable — the
  mutation-audit recorded as the manifest's negative control, and spot-audited on a sample;
- every surfaced bug is fixed-with-test, parked with a reason, or handed to `clean-sweep`;
- no assertion was weakened to pass — the diff is audited for it;
- coverage before/after is pasted — but the pass criterion is the mutation-audit set, never
  the percent.

## A worked example

The ask: the payments module reports 12% branch coverage and everyone is afraid to touch it.

**Map → scope confirm (your gate).** Coverage gaps crossed with the call graph of money paths
yields nine critical surfaces: charge, refund, webhook signature verify, retry dedupe… You
approve the list — that confirmation is what makes the denominator finite and DONE checkable.

**Characterize.** Workers assert what the code actually does, not what anyone wishes. The
refund test discovers the module floors to cents in the customer's favor on one branch and
against them on another. That is a surfaced bug, and it triggers the behavior call — your other
gate: load-bearing quirk or defect? You rule defect; the fix lands in-PR with the
characterization test flipped to assert the correct behavior, red-first.

**Mutation audit.** Every green test must prove it can die. The refund suite's boundary is
mutated (`>=` → `>`): the targeted assertion fails — the test bites. A test that survives its
mutation is a tautology and goes back to its worker.

```
| task_p4 | refund rounding | CHAR t | MUT t | REVIEWED t | MERGED t |  | PR #87, mutation log docs/reports/p4/ |
```

**Re-map → terminal.** Coverage re-maps until the confirmed surface is exhausted: **COVERED**,
with one webhook-replay edge parked `needs-human` (it needs a production key the fleet cannot
hold) — so honestly, **COVERED-WITH-PARKED**.

## Failure modes this mission is built to prevent

| Anti-pattern                              | Why it burns you                                           |
|-------------------------------------------|------------------------------------------------------------|
| Chasing the coverage percent              | 100% with tautological asserts proves nothing              |
| A green test whose mutation also passes   | Insensitive to the behavior — worse than no test           |
| A compile break as the mutation proof     | Proves source-shape dependence, not behavior sensitivity   |
| Asserting a surfaced bug as correct       | Freezes the defect into the behavioral contract            |
| An unbounded surface                      | No confirmed critical list, no denominator, no convergence |
| Expected values recomputed the code's way | A tautological test that can never fail                    |

## Composes
Playbooks:
[`characterize`](../../playbooks/characterize.md) ·
[`build-change`](../../playbooks/build-change.md) ·
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`runtime-prove`](../../playbooks/runtime-prove.md) ·
[`compound-learn`](../../playbooks/compound-learn.md) ·
[`design-twice`](../../playbooks/design-twice.md) ·
[`mutation-hunt`](../../playbooks/mutation-hunt.md) (deferred: loaded at build-blind review)

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

- [`deflake-it`](deflake-it.md) — make the suite stable enough to trust before proving with it.
- [`clean-sweep`](clean-sweep.md) — where ambiguous surfaced bugs go to be closed properly.
- [`ship-it`](ship-it.md) — new work arrives with its tests built in, failing test first.
