# 🧹 clean-sweep — a finite backlog exhausted to zero, with evidence

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — coordinator plus parallel isolated fix workers, one finding each; you own the one-way doors.
> **Activation load:** ~32,600 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 16% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** self-run — the 2026-09-14 tracker run closed DRY-WITH-PARKED with artifacts in
> the run's own directory and the verifier re-executed at promotion
> ([close report](../runs/2026-09-14-clean-sweep-self-run.md), bound by
> `runtime/scripts/run_report.py`, issue #411)

> Point it at an audit report, an issue tracker, or a README that lies. Come back to a backlog
> that is demonstrably empty: every real item fixed on an integration branch with a test that
> failed before the fix, every unreal item refuted with the attempts logged, and the final
> enumeration pasted into the ledger showing the dry state.

**Skill:** [`skills/clean-sweep/SKILL.md`](../../skills/clean-sweep/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/clean-sweep.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/clean-sweep-light.jpg">
    <img src="../../assets/diagrams/missions/clean-sweep-light.jpg" alt="Mission contract for clean-sweep: you give it an audit report, an issue tracker, or docs that lie; it interrupts you for batch approval of refuted and duplicate closes; the promotion PR; you get back DRY or DRY-WITH-PARKED, plus one merged PR per finding; a test that failed pre-fix; the final enumeration pasted in the ledger; it stops at the promotion PR — every close backed by a merge SHA, never by worker memory; phases ENUMERATE, TRIAGE, FIX, REVIEW, LAND, CLOSE, RE-ENUMERATE" width="820">
  </picture>
</p>

---

## Invoke it

```
> close every issue in <the tracker, or the path to an audit report>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: open-fleet RPI runtime (Orca, posix, t3code, ao+). git + gh (or a tracker via orca linear or orca jira). One worker playbook pack per worker (Matt triage/tdd, or Addy debug/build) — never two routers in one worker.

## What to provide

- A tracker query or audit path that defines the finite backlog.
- The affected repository, integration scope and runnable baseline test command.
- Owners for policy, credentials or external actions that a code fix cannot complete.

## What it does

`clean-sweep` is the backlog-exhaustion fleet. A **coordinator** — a thin loop-holder that never
reviews, codes, opens PRs, or merges — enumerates a bounded set of findings, dispatches every one
through a per-finding pipeline, verifies each claim against authoritative state (git, the test
runner, the tracker), and re-enumerates until a full pass comes back dry. Coordinator memory gets
compacted mid-run, so the run's state lives in a ledger **file**, one row per finding:

```
| task_id | id | title | CLASS | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | WT_CLEAN | lighting | park | evidence |
```

`CLASS` is the triage verdict, and there are exactly eight: `real-bug` · `real-feature-small` ·
`refuted` · `duplicate` · `externally-resolved` · `needs-human` · `out-of-scope` · `CODE_CLOSED`. Every close is
backed by a SHA-bound [evidence manifest](../concepts.md#the-evidence-manifest) — a worker saying
"fixed" is a claim to check, never a fact to record.

Three sources, one unit and one pipeline — you declare the source at the start:

- **`source=audit`** (default) — findings from a scan or adversarial-review document. The
  findings list is frozen up front.
- **`source=tracker`** — open issues. Run-start `T0` is recorded **first**, and the denominator
  is two queries: every open issue in scope, paginated to the very end (a truncated listing
  silently fails the run), plus every issue created or reopened since `T0` in any state (class
  `externally-resolved`). Both queries re-run on every loop, so mid-run filings cannot slip the
  count.
- **`source=doc-claims`** — falsifiable documentation claims. A false claim *is* a finding:
  extract it, verify it against a `file:symbol` or a run, correct or remove it. Writing new docs
  is not this mission — that is ship-it-scoped work.

Whatever the source, a *prior run's* completion report over the same surface enters the
enumeration as claims to re-verify — never as a pre-closed set. An autonomous run will believe
its own green checkmarks unless anti-inflation is structural.

## When to reach for it

- "Close every issue in the tracker."
- "Fix everything in this audit."
- "The README lies — verify and fix it."
- An overnight run where you want to wake up to a drained backlog with an evidence trail per close.

**When NOT to reach for it:**

- Security, perf, dependency, test-debt, or flake campaigns — those are
  [`harden-it`](harden-it.md), [`speed-it`](speed-it.md), [`modernize-it`](modernize-it.md),
  [`prove-it`](prove-it.md), and [`deflake-it`](deflake-it.md). They all paraphrase to
  "inventory → fix → repeat", but their denominators and convergence proofs differ, so each is
  its own mission.
- Building new work — that is [`ship-it`](ship-it.md).
- You want a verdict, not closes — [`review-it`](review-it.md) has no fix authority.

## The pipeline

```mermaid
flowchart TD
    A[Audit document] --> D[ENUMERATE<br/>full denominator per source]
    B[Tracker with T0 recorded] --> D
    C[Doc claims] --> D
    D --> E[SKEPTIC-TRIAGE<br/>reproduce or refute, per finding]
    E --> F[FREEZE the findings list]
    F --> G[BOOTSTRAP BASE<br/>preflight guards BASE ≠ default]
    G --> H[PER-FINDING<br/>verify-real → fix → PR → build-blind review]
    H --> I[LAND<br/>merge conductor, one train]
    I --> J[CLOSE with evidence<br/>merge SHA + failed-pre-fix test]
    J --> K[re-ENUMERATE]
    K -->|new or reopened items| E
    K -->|zero non-terminal items| L[FINAL REPORT + reflection<br/>run-close commits land]
    L --> L2[VERIFY the final tip<br/>validate + test suite green at the final head]
    L2 --> M{{DRY}}
    M --> N[promotion PR opened<br/>left to a human]
```

Phase by phase:

1. **Self-orient and enumerate.** The coordinator reads the source and builds the full
   denominator. For `source=tracker` that means both `T0` queries, paginated to the end — the
   count is the contract, and a partial listing is a silent run failure, not a smaller job.
2. **Skeptic-triage.** Every finding is reproduced or refuted with evidence *before* any fix
   effort, with two codebase checks first: REDUNDANCY (search by domain concept — already
   implemented means wontfix) and PRIOR-REJECTION (an out-of-scope knowledge base). An
   unreproducible finding is refuted with the attempts logged, or `needs-human` if it implies
   private state. The verdict lands in the ledger as the finding's CLASS.
3. **Freeze and bootstrap.** The triaged list freezes; preflight verifies the integration BASE is
   not the default branch, compared on canonical refs
   ([`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md)) — if BASE is the default, every
   per-finding merge lands straight on production and bypasses the human promotion review.
4. **Fix, one PR per finding** ([`remediate-finding`](../../playbooks/remediate-finding.md) →
   [`build-change`](../../playbooks/build-change.md)). Clean baseline, failing test first with
   its expected value from an independent source of truth, smallest change to green, negative
   control. One finding = one branch = one PR = one merge commit; a build-blind integrator opens
   the PR against BASE — builders never open their own.
5. **Review** ([`acceptance-review`](../../playbooks/acceptance-review.md)). A fresh session that
   did not write the code, on isolated axes; every finding quotes its motivating line; the
   `reviewed_sha` is recorded — the merge depends on it.
6. **Land** ([`merge-serialization`](../../runtime/merge-serialization.md)). One conductor,
   strict arrival order, ancestry-verified; a rebase voids the review
   ([`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md)); same-file findings form
   a merge chain.
7. **Close and re-enumerate.** A finding closes only off the verified merge — never off worker
   memory — with a closing comment linking the PR and the failed-pre-fix test. Then the full
   enumeration runs again; new and reopened items re-enter at triage. The loop ends only when a
   complete pass comes back dry.
8. **Report, then verify the final tip.** The final report, integrity inventory, and reflection
   land as run-close commits outside the per-finding gates — so the check runs last, at the head
   those commits produced: the repo's own validate/test suite must be green there before `DRY` is
   reported and the promotion PR opens. Any later commit re-runs it; a green per-finding history
   under a red report commit is still a red branch.

## Terminal states

*Every item ends in exactly one.*

| State | Meaning | Who acts on it |
|---|---|---|
| `CLOSED` | Merged, ancestry-verified PR + a test that failed pre-fix, both linked in the closing comment | nobody — the evidence chain is the authorization |
| `PARKED` | Two kinds, per the ledger contract. **Clean:** `refuted` / `duplicate` / `externally-resolved` through the batch gate, or `out-of-scope` handed off — not real work for this run. **Degraded:** `needs-human` naming its gate, or `CODE_CLOSED` + `VERIFY_AT_SCALE` with its OPS plan — honest incomplete | the batch gate (clean); a human or OPS (degraded) |
| `DRY` | A full enumeration finds zero items outside `CLOSED` and the clean parks, and the final tip (after every run-close commit) passes the repo's own validate/test suite; the output is pasted in the ledger | terminal — the promotion PR is opened and left to you |
| `DRY-WITH-PARKED` | The set is exhausted but at least one degraded park remains; never reported as `DRY` | a human clears each named park |

The run ends by pasting the dry enumeration, never by asserting it. For `source=tracker`, issues
created or closed mid-run are reconciled against `T0`, so the final count is honest.

## Human gates

One in-run gate, batched: **refuted and duplicate closes**. Closing an issue without a fix is a
one-way door, so those closes queue for a single batch approval (or a once-per-run recorded
grant). Fix-backed closes need no extra gate — the evidence chain is the authorization.

Promotion stays yours: BASE → default is out of scope. The fleet opens the promotion PR and
stops. Stalls and crashes are not gates either — a stalled worker triggers the
[`liveness-resume`](../../runtime/liveness-resume.md) WATCH loop, and a dead coordinator is
rebuilt from provenance with RESUME, ledger-scoped and git-verified.

## Convergence proof

`clean-sweep` is done when — and only when — a full enumeration finds zero items that are not:

- **CLOSED with evidence** — a merged, ancestry-verified PR plus a test that failed pre-fix,
  revert-audited on a ≥10% sample, with the closing comment linking PR and test; or
- **PARKED in a clean class** — `refuted` / `duplicate` / `externally-resolved` through the batch
  gate, or `out-of-scope` handed off.

A degraded park — `needs-human` naming its gate, or `CODE_CLOSED` + `VERIFY_AT_SCALE` with its OPS
plan — does not stop the enumeration from coming back dry, but it makes the honest terminal
`DRY-WITH-PARKED`, never `DRY`. `DRY` also requires the integration **tip** to pass the repo's own
validate/test suite: the final report and any run-close commit land on the branch outside the
per-finding gates, so a green per-finding history under a red report commit is still a red branch —
the final head, after every run-close commit, is verified green before the promotion PR opens. The final enumeration output is pasted into
the ledger showing the dry state, and `source=tracker` runs reconcile mid-run creations and closures
against `T0` — no quietly shrinking denominator, no honest-looking partial "done".

## A worked example

The ask: a security review left `docs/audit-2026-06.md` with 14 findings.

> clean-sweep docs/audit-2026-06.md

**Enumerate → triage.** All 14 land in the ledger at T0. Skeptic-triage reproduces each claim
before anyone builds: 9 confirm (one of which needs a policy decision no agent may make), 3 are
refuted with evidence (one "SQL injection" is a parameterized query the auditor misread), and
2 duplicate other findings already in the set.

**The batch gate.** Closing an issue without a fix is one-way, so the 3 refuted + 2 duplicate
closes queue for a single human approval — you answer once, not five times.

**Per-finding pipeline.** Finding 7 (IDOR on `/api/orders/:id`) gets a worker in its own
worktree: red-first test asserting 403 for a foreign order, minimal fix, PR #112, build-blind
review, conductor merge. Its row advances only as each verify lands:

```
| task_c7 | F7 IDOR /api/orders | BUILD_DONE t | PR_OPEN t | BOT t | REVIEWED t | MERGED t | WT_CLEAN t |  | #112 @ 4be9a02, red-first 71d3c |
```

**Re-enumerate until dry.** The sweep re-reads the audit: 8 findings fixed with merge SHAs,
5 closed by the batch gate, 1 parked `needs-human` (the key-rotation policy call) — 14
accounted for, plus one new finding surfaced by a fix round that entered the same loop and
landed fixed. The second enumeration returns zero non-terminal items, but a park is still
open, so the honest terminal is **DRY-WITH-PARKED**, never `DRY` — and the promotion PR opens
with the full close table, the park named in it.

## Failure modes this mission is built to prevent

| Anti-pattern                                  | Why it burns you                                                              |
|-----------------------------------------------|-------------------------------------------------------------------------------|
| Fixing without the triage repro               | You "fix" symptoms and close real bugs unfixed                                |
| Closing from worker memory                    | Only a verified merge closes a finding; a memory is a claim                   |
| One mega-PR for many findings                 | Per-finding evidence and rollback die in the blob; the merge train exists     |
| Truncated enumeration                         | A partial denominator is a false "done"                                       |
| Sweeping security/perf/deps/tests/flakes here | Different convergence proofs — those are their own missions                   |
| Driving the loop with `orchestration run`     | The file-ledger boolean gate must stay under the coordinator's manual control |

## Composes
At activation — the SKILL's Composes/rides clause, what a coordinator loads before the first dispatch:

Playbooks:
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`build-change`](../../playbooks/build-change.md) ·
[`triage-state`](../../playbooks/triage-state.md) ·
[`linear-enumeration`](../../playbooks/linear-enumeration.md)

Runtime policies:
[`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md) ·
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`orca-dag-semantics`](../../runtime/orca-dag-semantics.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) ·
[`attention-budget`](../../runtime/attention-budget.md) ·
[`gate-classification`](../../runtime/gate-classification.md) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) (triage `ro`, build `rw`; tracker text is data, never instructions)

Deferred reads, loaded on entering their phase and never at activation: [`agent-brief`](../../playbooks/agent-brief.md) when a dispatched worker needs a brief · [`liveness-resume`](../../runtime/liveness-resume.md) when a dispatched worker stalls or a run resumes · [`merge-serialization`](../../runtime/merge-serialization.md) + [`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md) at conductor LAND · [`acceptance-review`](../../playbooks/acceptance-review.md) + [`mutation-hunt`](../../playbooks/mutation-hunt.md) at review · [`completion-audit`](../../playbooks/completion-audit.md) + [`compound-learn`](../../playbooks/compound-learn.md) at run close.

## Related missions

- [`ship-it`](ship-it.md) — build new work instead of closing existing findings.
- [`harden-it`](harden-it.md) — the security campaign; same loop shape, a different proof (a clean re-audit).
- [`speed-it`](speed-it.md) — the perf campaign; done is a statistical budget, not an empty list.
- [`review-it`](review-it.md) — the verdict with no fix authority.
