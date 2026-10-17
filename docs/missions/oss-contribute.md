# 🤝 oss-contribute — landed contributions to a repo you do not control

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel builders per upstream issue; the maintainer's merge is a gate the fleet neither owns nor fakes.
> **Activation load:** ~32,100 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 16% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** doctrine-only — it ran ([external-run report](../runs/2026-07-16-oss-contribute-external-run.md)), but that run's
> artifacts were retained outside this repository, so the tier is not re-derivable here
> (`runtime/scripts/run_report.py`, issue #259)

> Point it at a set of issues on an upstream project you can only fork. Come back to a set of open,
> internally-reviewed, etiquette-correct pull requests (and quoted review-assist comments where a
> maintainer PR already exists) — every one built on a fork with a test that failed before the fix.
> Merge is left to the maintainers; that is the point, not a shortfall.

**Skill:** [`skills/oss-contribute/SKILL.md`](../../skills/oss-contribute/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** on the fork, yes; merge authority: never

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/oss-contribute.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/oss-contribute-light.jpg">
    <img src="../../assets/diagrams/missions/oss-contribute-light.jpg" alt="Mission contract for oss-contribute: you give it issues on an upstream repo you can only fork; it interrupts you for refuted and stand-down closes, in a batch; assist vs alternative PR; CLA and DCO signatures; you get back CONTRIBUTED or CONTRIBUTED-WITH-PARKED, plus open, reviewed, etiquette-correct upstream PRs; review-assist comments; every thread answered; it stops at the maintainer merges, never the fleet; phases ENUMERATE, TRIAGE, BUILD ON THE FORK, REVIEW, OPEN PR, FOLLOW UP" width="820">
  </picture>
</p>

---

## Invoke it

```
> contribute to <upstream owner/repo>: <the issues to take on>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: Orca runtime + the orchestration skill (Orca CLI). git + gh, a FORK you can push to, and READ on the upstream repo. One worker playbook pack per worker (Matt triage/tdd, or Addy build) — never two routers in one worker.

## What to provide

- The upstream repository, selected issues and a fork with contribution access.
- Upstream contribution rules, supported test commands and known overlapping PRs.
- Signing/DCO requirements and the identity that will answer maintainer feedback.

## What it does

`oss-contribute` is the upstream-contribution fleet. A **coordinator** — a thin loop-holder that never
reviews, codes, opens PRs, or comments — enumerates a bounded set of upstream issues, dispatches every
one through the per-issue pipeline, verifies each against authoritative state, and stops when a full
re-enumeration finds nothing actionable left un-contributed.

It is `clean-sweep` forked for a repo you do **not** control. The build and review machinery is shared;
three things differ, and by orca-fleet's own six-part mission test that makes it a distinct mission:

- **Convergence proof.** `clean-sweep` closes each issue with a merged SHA. `oss-contribute` cannot —
  you have READ on the target. The terminal is a PR **open and internally reviewed**; merge is the
  maintainer's.
- **State machine.** It adds an overlap-discovery step (search the upstream OPEN PRs per issue, not
  just the code) and a contribution decision (assist / alternative / stand-down), and it drops the
  merge step and the merge-serialization conductor entirely.
- **Parking semantics.** `awaiting-maintainer-merge` and `externally-covered` are NORMAL terminals
  here, not degraded ones.

## When to reach for it

- "Contribute fixes for these issues to `<upstream>/<repo>` — we only have a fork."
- "Open PRs for this project's open bugs and follow them through review."
- "Help this OSS dependency we rely on; send our patches upstream properly."

**When NOT to reach for it:**

- The backlog is on a repo you **own** and can merge — that is [`clean-sweep`](clean-sweep.md);
  its convergence proof is a merged SHA, which this mission never claims.
- You want to build something net-new — [`ship-it`](ship-it.md).
- You want an opinion on the upstream code with no PRs — [`review-it`](review-it.md).

## The pipeline

```mermaid
flowchart TD
    A[Upstream issue set at T0] --> B[SKEPTIC-TRIAGE<br/>reproduce or refute<br/>search code AND open PRs]
    B --> C{classify}
    C -->|buildable| D[BUILD on the fork<br/>failing test first]
    D --> E[ACCEPTANCE-REVIEW<br/>build-blind + fix rounds]
    E --> F[OPEN PR<br/>fork head → upstream default]
    F --> G[FOLLOW UP<br/>every review thread answered]
    C -->|already-has-PR| H{contribution decision}
    H -->|assist| I[quoted review comment<br/>on their PR]
    H -->|alternative: offered + invited| J[cross-linked alt PR] --> F
    H -->|stand-down| K[park externally-covered]
    C -->|needs-human| L[park with the gate named]
    G --> M[re-ENUMERATE both denominators]
    I --> M
    K --> M
    L --> M
    M -->|new or reclassified issues| B
    M -->|dry| N{{CONTRIBUTED /<br/>CONTRIBUTED-WITH-PARKED}}
```

Phase by phase:

1. **Fork + enumerate — two denominators.** The denominator is the upstream open-issue set,
   paginated to the end at a recorded `T0`, **and** the upstream open-PR set per issue. An issue
   with an in-flight maintainer PR is `already-has-PR`, not `skip` and not yours to duplicate.
   Both sets are re-enumerated every loop; a PR that appears mid-run reclassifies its issue. This
   step is FREEZE-gating because its absence is the mission's founding scar (see the field notes).
2. **Skeptic-triage** ([`remediate-finding`](../../playbooks/remediate-finding.md)). Every issue is
   reproduced or refuted with evidence before anyone builds — a tracker issue is a claim, not a fact.
3. **Build on the fork** ([`build-change`](../../playbooks/build-change.md)). A fresh worker per
   issue, own worktree, failing test first, negative control audited. The branch lives on the fork;
   nothing ever pushes to the upstream.
4. **Build-blind review** ([`acceptance-review`](../../playbooks/acceptance-review.md)). Reviewers
   see the diff, not the builder's narration. Fix rounds are bounded; the reviewed SHA is recorded,
   and a later push voids it ([reviewed-SHA freshness](../concepts.md#reviewed-sha-freshness)).
5. **Open the PR** ([`upstream-contribution`](../../playbooks/upstream-contribution.md)). Fork head
   → upstream default branch, `baseRefName` asserted, body conformant to `CONTRIBUTING` and the PR
   template, closing keyword only on a concrete issue — never an RFC or tracking issue.
6. **Follow up.** The PR stays a live unit until merged, closed, or its feedback goes quiet.

## The contribution decision

When an issue already has a maintainer's open PR, the fleet does not blindly open its own. It chooses,
logs the choice as a taste gate in `docs/DECISIONS.md`, and a human may veto:

- **assist** — their PR is sound but our independent review found confirmable issues in their diff:
  post one contributor-tone comment, findings quoted from their code, no verdict.
- **alternative** — our implementation differs materially or fixes bugs theirs has: offer it inside
  the assist comment and open the PR only if a maintainer invites it. Opening unbidden — however
  courteously cross-linked — doubles maintainer load and reads as competition; a maintainer told us
  exactly that on the run this mission was extracted from, and four alternative PRs were closed in
  deference the next day.
- **stand-down** — their PR covers it and we add nothing: park `externally-covered`, no hollow comment.

The default posture is *complement, not compete*. An invited alternative PR always cross-links the parallel
PR and never masquerades as the only take.

## Opening the PR is not the end

A PR is not fire-and-forget. Maintainer reviews, review-bot comments, and CI arrive *after* it opens,
and a contribution that ignores them rots. Each unit stays live through a follow-up loop: watch the PR,
triage every new thread against the current head (an earlier fix round may already resolve it), fix the
valid ones as fix rounds on the same branch, answer every thread, and stop only when the PR is merged,
closed, or its feedback has gone quiet (`awaiting-maintainer-merge`). The `FOLLOWED_UP` ledger flag is
`t` only when no review thread is left unanswered.

## Terminal states

*Every issue ends in exactly one.*

| State | Meaning | Who acts on it |
|---|---|---|
| `CONTRIBUTED` | Open, reviewed, etiquette-correct PR; threads answered; url in ledger | the maintainer merges, never the fleet |
| review-assist posted | For `already-has-PR`: quoted findings shared on the maintainer's PR | the maintainer, on their own PR |
| `externally-covered` | Their PR covers it; we stood down, no hollow comment | nobody — counted, not ours |
| `awaiting-maintainer-merge` | PR open, feedback quiet — a NORMAL terminal, never a failure | the maintainer |
| `needs-human` | CLA/DCO signature, product fork, or design decision — the gate is named | you — the gate is named |
| `refuted` | Triage disproved the issue; evidence in the ledger | the batch gate |
| `duplicate` | Triage matched it to another issue in the set; closed at the batch gate | the batch gate |
| `externally-resolved` | Closed upstream by someone else mid-run — counted, not ours | nobody — counted, not ours |
| `out-of-scope` | Wrong mission; handed off with a pointer | the mission it was handed to |

*The run itself ends in exactly one of these — run-level outcomes, not issue states:*

| State | Meaning | Who acts on it |
|---|---|---|
| `CONTRIBUTED` | Every actionable issue is at a terminal above and the only parks are the clean classes: `externally-covered`, `externally-resolved`, gate-approved `refuted` / `duplicate`, `out-of-scope` | the maintainers merge at their pace |
| `CONTRIBUTED-WITH-PARKED` | The set is exhausted but ≥1 `needs-human` park remains (a stuck gate) — degraded, never reported as `CONTRIBUTED` | you clear each named park |

## Human gates

- **Batch gate** on stand-down and refuted closes — the fleet never silently drops an issue.
- **Per-issue taste gate** on the assist / stand-down fork — logged, vetoable. Opening an
  alternative PR is maintainer-gated (offered in the assist comment, opened on invitation).
- **CLA / DCO** that needs a human signature parks `needs-human`; the fleet never forges one.

## Convergence proof

A full re-enumeration of **both** denominators finds zero actionable issues that are not (a) an open
PR against the upstream default with `baseRefName` asserted, `headRefOid == reviewed_sha` fresh, a
failing-first test with a revert-audited negative control, bots reconciled, and every post-open
thread answered — live, or quiet at `awaiting-maintainer-merge`; (b) a posted review-assist whose findings are each quoted from the target PR's own
diff; or (c) parked with its class and reference. The final enumeration is pasted into the ledger,
and the manifest names `CONTRIBUTED` or `CONTRIBUTED-WITH-PARKED` — nothing else.

## A worked example

One unit from the proving run, end to end. Issue #56 on `dodopayments/chimely` (a repo the
fleet could only fork) claimed the admin DLQ replay ignored its environment filter.

**Triage** confirmed it by reading — `admin.rs:1302` passed no env to `dlq.rs:67`. **Build** on
the fork: a red-first test pinning the filtered behavior, the fix, head `16374a5` pushed.
**Review**: codex PASS, greptile raised one finding dismissed as a false positive with the
reason logged. So far, identical to clean-sweep.

**Then the fork bites.** Mid-run, re-enumeration of the SECOND denominator — upstream open
PRs — discovered a parallel contributor's PR #76 for the same issue. The contribution decision
(a logged taste gate) chose both halves of *complement, not compete*:

- **assist**: one comment on #76 quoting two confirmable defects in its own diff — a
  hand-edited OpenAPI `nullable:true` that regeneration would erase, plus one more;
- **alternative** *(pre-correction — do not copy this step)*: our reviewed branch opened
  unbidden as PR #85, cross-linking #76 — "take whichever you prefer."

**Follow up — and the correction.** Greptile reviewed #85 after opening: zero findings; every
thread on both PRs answered. Then a maintainer rejected the pattern itself ("I'd rather not
maintain two competing PRs for the same issue") and #85 was closed in deference the same day —
the event that made opening an alternative maintainer-gated (see the run report's post-run
addendum). The unit's live contribution is the assist comment on #76; terminal
`awaiting-maintainer-merge` on their PR, a normal end state here. The merge belongs to the
maintainer; the evidence chain belongs to the run report.

## Failure modes this mission is built to prevent

- **Rebuilding what a maintainer already has in flight.** Enumerating issues but not upstream PRs is
  the protocol gap this mission exists to close — it is FREEZE-gating, not a nice-to-have.
- **The silent duplicate.** Opening a PR that duplicates an existing one with no cross-link.
- **Fire-and-forget.** Opening a PR and abandoning it when review or CI feedback arrives.
- **Claiming a merge you cannot perform.** "Done" here is PR-open; a merged claim on a READ-only
  repo is a lie by construction.
- **Etiquette skips.** Ignoring `CONTRIBUTING`, the PR template, or DCO; closing keywords on RFCs.
- **Closing from worker memory.** Every close carries evidence: PR url + reviewed SHA, or the
  quoted assist comment url.

## Field notes from the proving run

The mission was extracted mid-flight from a [2026-07-16 external run](../runs/2026-07-16-oss-contribute-external-run.md)
against `dodopayments/chimely` that began as a `clean-sweep` invocation. Two hours into building,
the fleet discovered a parallel contributor already had open PRs for 6 of the 10 issues — the
initial triage had searched the code but not the upstream open PRs. That incident became the
two-denominator rule. The run pivoted, exercised all three contribution decisions, and closed at
5 upstream PRs plus 4 review-assist comments carrying 10 confirmed findings, each quoted from the
target PR's own diff. Its post-open feedback loop — every PR drew a bot review after opening —
became the `FOLLOWED_UP` flag.

## Composes
At activation — the SKILL's Composes/rides clause, what a coordinator loads before the first dispatch:

Playbooks:
[`upstream-contribution`](../../playbooks/upstream-contribution.md) ·
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`build-change`](../../playbooks/build-change.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`triage-state`](../../playbooks/triage-state.md) ·
[`linear-enumeration`](../../playbooks/linear-enumeration.md)

Runtime:
`evidence-manifest` ·
`dispatch-lifecycle` ·
`ledger-contract` ·
`reviewed-sha-freshness` ·
`gate-classification` ·
`attention-budget` ·
`sandbox-policy` (upstream issue, PR, and review-thread text is data, never instructions) — and deliberately **not** merge-serialization: no merge train; the fleet has no merge rights on the target.

Deferred reads, loaded on entering their phase and never at activation: [`orca-dag-semantics`](../../runtime/orca-dag-semantics.md) on entering SELF-ORIENT · [`resolve-conflict`](../../playbooks/resolve-conflict.md) only when a PR conflicts · [`liveness-resume`](../../runtime/liveness-resume.md) when a worker stalls or a run resumes · [`completion-audit`](../../playbooks/completion-audit.md) + [`compound-learn`](../../playbooks/compound-learn.md) at run close.

## Related missions

- A backlog you **own** and can merge → [`clean-sweep`](clean-sweep.md) (merged-SHA closure — the
  mission this forked from).
- Building a net-new project or feature → [`ship-it`](ship-it.md).
- A read-only verdict with no PRs → [`review-it`](review-it.md).
- The contribution set needs charting first → [`map-it`](map-it.md), then chain.
