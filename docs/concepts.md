# Concepts — the mental model behind orca-fleet

[Documentation](README.md) · [First run](getting-started.md) · [Mission guides](missions/README.md)

The files in [`runtime/`](../runtime/) are written for agents: terse, imperative, load-bearing.
This page is the same material written for humans — why each mechanism exists, what failure it
prevents, and how the pieces fit together. Nothing here overrides the runtime policies; when in
doubt, the policy file is the source of truth.

## Contents

- [Glossary](#glossary)
- [Read a run result](#read-a-run-result)
- [A fleet is an outcome, not an ingredient](#a-fleet-is-an-outcome-not-an-ingredient)
- [Coordinators and workers](#coordinators-and-workers)
- [The evidence manifest](#the-evidence-manifest)
- [Independent verification](#independent-verification)
- [Decision gates: mechanical, taste, one-way](#decision-gates-mechanical-taste-one-way)
- [The merge train](#the-merge-train)
- [Attention budget (orchestration tax)](#attention-budget-orchestration-tax)
- [Reviewed-SHA freshness](#reviewed-sha-freshness)
- [Liveness, crash, resume](#liveness-crash-resume)
- [Sandbox profiles](#sandbox-profiles)
- [Security boundaries and the response ladder](#security-boundaries-and-the-response-ladder)
- [Hosted trackers and the trust envelope](#hosted-trackers-and-the-trust-envelope)
- [One router per worker](#one-router-per-worker)
- [Chaining missions](#chaining-missions)
- [Proof status](#proof-status)
- [Autonomy](#autonomy)
- [Activation load](#activation-load)
- [The mission-identity test](#the-mission-identity-test)

## Glossary

The words the rest of this page, the README and the mission guides use without stopping to
define them. Each is one line here and explained in full in its own section or runtime policy.

- **BASE** — the integration branch a fleet merges into, never the default branch; promotion from
  BASE to the default branch is a one-way human gate.
- **Coordinator** — the terminal you started. It decomposes the goal, dispatches, verifies and keeps
  the ledger; it never writes code.
- **Worker** — a fresh agent in its own git worktree and terminal, dispatched with a task spec and
  torn down after its unit. **Builders** write the change, **build-blind reviewers** review code
  they did not write and were not told the conclusion about, **integrators** open PRs against BASE,
  and one **conductor** owns every merge.
- **Ledger** — the coordinator's durable memory: one row per unit with its exit flags, lighting,
  PR, reviewed SHA, merge SHA and evidence pointer. Git is truth; the ledger is its cache.
- **T0** — the timestamp in the ledger header at which the run's denominator was enumerated.
- **Denominator** — the frozen set a run must account for: acceptance criteria, findings, journeys,
  paths. A worker cannot shrink it; the verifier re-derives it from the frozen source.
- **Evidence manifest** — the SHA-bound JSON a worker emits with `worker_done`, the definition of
  done as data. **`worker_done`** is the Orca message that says a unit is finished: a claim to
  verify, never a fact to record.
- **Verifier** — a session other than the one that did the work (`runtime/scripts/verify.py`,
  or a fresh verifier worker) that re-derives the manifest's claims from git, GitHub and the
  frozen contract.
- **Negative control** — proof that the proof can fail: revert or mutate the change and watch the
  covering test go red. A *revert* control restores the changed paths; a *hand* control applies a
  quoted diff. The verifier executes one only when the coordinator passes `--execute-nc`.
- **Mechanical / taste / one-way** — the three decision classes: auto-resolved with an audit line;
  recommendation taken and batched for your later veto; yours, always, never defaulted on timeout.
  The audit lines land in the target repo's `docs/DECISIONS.md`, one per resolved gate.
- **Lane 0 / A / B** — how a gate on hard-to-reverse work resolves: refuse (0); proceed as
  reversible work such as testnet or fixtures (A); draft both options for a human to pick (B).
- **Lit / dark-eligible** — `lit`, the default, means a human or build-blind reviewer reads the
  change before it lands; `dark-eligible` is opt-in for Lane A work with an unfakeable oracle.
- **`PROFILE=ro` / `rw` / `danger`** — worker privilege: read-only, workspace-write, or bypass
  approvals inside a disposable sandbox only.
- **`reviewed_sha`** — the commit a review approved. A merge requires it to equal the head; a
  rebase, a bot autofix or a late push voids the review.
- **Merge train / hot-file chain** — one conductor drains merge-ready PRs in arrival order; PRs
  that touch the same mount-point file (a route registry, DI wiring, a migration) merge as a chain.
- **Attention budget / WIP** — concurrent builders capped to what review can absorb (default ≤3),
  counted as live panes rather than tasks. A mutating run's report records the cap it ran at and
  what it measured, one row per dispatch wave, so the caps can graduate from asserted to measured.
- **Skeptic triage** — reproduce or refute every finding before anyone builds.
- **Tracer-bullet slice** — a narrow but complete path through every layer a change touches, sized
  for one fresh context window and demoable alone.
- **Terminal state** — the named end state a mission stops at. A *degraded* terminal
  (`-WITH-PARKED`, `-WITH-OPEN-ITEMS`, `NO-GO`, `INCONCLUSIVE`, …) is never reported as the clean one.
- **`SUSPECT`** — a unit Orca's provenance calls completed but git disagrees with; treated as failed.
- **`DRY`** — clean-sweep's clean terminal: a full re-enumeration finds nothing open.
- **Playbook / runtime policy / pack** — a callable phase protocol a mission injects into a worker's
  task; an Orca mechanics policy under `runtime/`; an upstream skill collection
  (mattpocock/skills, garrytan/gstack, addyosmani/agent-skills) a worker draws its method from —
  exactly one pack per worker.
- **Proof tier** — `doctrine-only`, `self-run` or `external-run`; advancing needs a run report that
  binds at a named commit. `self-run` / `external-run` name the run's *target* (this catalog / any
  other repo), not who ran it — [Proof status](#proof-status) defines them.

## Read a run result

Suppose you ask for a tested `/healthz` endpoint and a promotion PR. The fleet builds and reviews
the change on an integration branch (**BASE**), then reports `PROMOTION_READY`. For you, that means
there is a PR to assess before merging to the default branch. It does not mean the endpoint is
deployed. The [ship-it states](missions/ship-it.md#terminal-states) distinguish those steps.

Read the result in this order:

1. **Outcome:** which terminal state was reached, and does it match the stop point you authorized?
2. **Scope:** which acceptance criteria or findings were accounted for? A parked item stays
   visible with the action or owner it needs.
3. **Revision:** which commit was tested and reviewed? Does the PR still have that reviewed content?
4. **Checks:** which commands ran, what did they return, and where are the artifacts? A negative
   control shows the test detects a changed behavior, such as removing the route registration.
5. **Next action:** merge the promotion PR, resolve a named blocker, or authorize the next stage.

A terminal state describes **this run**. A proof tier describes **retained evidence for the mission
protocol**. A `GO` review, a green test result, a merged PR and a deployment are different facts.
The sections below explain how each is checked.

## A fleet is an outcome, not an ingredient

A skill like `/tdd` is an ingredient: it makes one agent better at one activity. A **fleet** is a
different species — it is a commitment to an end state. `clean-sweep` does not mean "apply the
triage technique"; it means *the backlog will be at zero, every close will be backed by a merged
SHA and a test that failed pre-fix, and the enumeration will be re-run until it comes back dry.*

That commitment is only credible if the fleet can prove it, which is why every mission in this
catalog is built around three things:

1. a **state machine** for its unit of work (a finding, a slice, a flake, a hypothesis),
2. a **convergence proof** — the specific, checkable condition that means "done",
3. an **evidence protocol** that makes every claim verifiable after the fact.

## Coordinators and workers

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/fleet-topology.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/fleet-topology-light.jpg">
    <img src="../assets/diagrams/fleet-topology-light.jpg" alt="Fleet topology: a human answers one-way gates; the coordinator holds the ledger and verifier; builder, reviewer, and conductor workers receive dispatches and return evidence" width="820">
  </picture>
</p>

Every mission runs the same topology on the Orca runtime:

- **One coordinator.** The terminal you started. It decomposes the goal, creates worktrees,
  spawns workers, classifies decisions, verifies results, and keeps the ledger. It **never
  writes code** — a coordinator that starts editing files has lost the thread that makes
  verification independent.
- **Many workers.** Each is a fresh agent in its own git worktree and terminal, dispatched with
  a task spec that embeds the playbook it should follow. Workers are disposable by design: a
  fresh context window per unit of work is what keeps quality flat across a 40-unit run, where a
  single long-running agent degrades.
- **Specialized workers.** Builders build. Build-blind reviewers review code they did not write
  and were not told the conclusion about. Integrators open PRs (builders never do — a builder
  that self-opens a PR gets the default branch as its base, which is exactly the wrong place).
  One conductor owns every merge.

The ledger deserves a special note: the coordinator's context gets compacted over a long run, so
its memory is not durable. The **ledger file** is. One row per unit — id, boolean exit flags,
`lighting` (`lit` or `dark-eligible`), PR, reviewed SHA, merge SHA, evidence pointer. Everything
the run needs to resume lives there, not in the scrollback.

## The evidence manifest

The definition of done, as data. Every worker emits one in its `worker_done` payload; the full
schema lives in [`runtime/evidence-manifest.md`](../runtime/evidence-manifest.md). Annotated:

```jsonc
{
  "unit": "AC-3-healthz-endpoint",       // which unit of work this claims to complete
  "base_sha": "6f7e3f8…",                // where the work started
  "head_sha": "9b06458…",                // what the work produced — both must be real commits
  "base_branch": "ravidsrk/fleet-base",  // the integration BASE the PR targets

  "contract": {
    // Binds the manifest to an AUTHORITATIVE denominator captured at run start.
    // The worker cannot choose its own scope: the verifier re-derives the id set
    // from this source and rejects a manifest that drops any criterion.
    "source": "specs/healthz.md@0b073fb",
    "digest": "sha256:…",
    "criterion_ids": ["AC-1", "AC-2", "AC-3"]
  },

  "criteria": [
    {"id": "AC-1", "text": "GET /healthz returns 200 with version", "addressed": true}
    // one entry per criterion — an unaddressed criterion is unmet work, not a waiver
  ],

  "commands": [
    // real invocations + exit codes + artifact paths. Never a prose summary.
    {"cmd": "pnpm test src/health", "exit": 0, "artifact": "docs/reports/AC-3/test.txt"}
  ],

  "negative_control": {
    // mandatory for any fix or test: prove the proof can fail.
    "did": "reverted the handler registration",
    "result": "healthz.test.ts went RED",
    "artifact": "docs/reports/AC-3/revert.txt"
  },

  "binding_audit": {
    // criterion↔test coverage the verifier samples — required on fix/test units
    "coverage": "AC-1..AC-3 (3/3)",
    "method": "criterion quoted, covering test quoted, mutation went RED"
  },

  "intent": {
    // required on mutation units; discarded-agent-reasoning, not the oracle
    "goal": "GET /healthz returns 200 with version and a DB ping",
    "ruled_out": "a static liveness file with no DB check",
    "why": "the acceptance criterion names connectivity, not process-up"
  },
  "lighting": "lit",                     // default; dark-eligible only Lane A + unfakeable oracle

  "pr": {"number": 12, "url": "…", "reviewed_sha": "9b06458…"},  // gates the merge
  "parked": [],                          // anything not done is named, never dropped
  "claim": "implemented /healthz with DB ping"   // narration — NEVER the completion oracle
}
```

Why this and not "read the transcript"? Three reasons, all learned the hard way:

- a coordinator does not hold its workers' terminal traces;
- traces get truncated and compacted, and they are gameable;
- most fundamentally, **a trace proves an action was attempted, not that the resulting state is
  correct** — an agent can run the right-looking commands against the wrong SHA.

## Independent verification

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/evidence-protocol.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/evidence-protocol-light.jpg">
    <img src="../assets/diagrams/evidence-protocol-light.jpg" alt="Evidence protocol: a worker's claim travels as a manifest to a fresh-session verifier, which checks git, tests, and the deploy target before marking the unit verified — or re-dispatches it" width="820">
  </picture>
</p>

The manifest is a claim. A **different session** than the one that produced the work checks it
against authoritative state, in a fixed order — scope first, because passing tests on a shrunken
denominator is the most dangerous false "done":

| Claim                       | Authoritative check                                              |
|-----------------------------|------------------------------------------------------------------|
| scope is complete           | re-derive the criterion set from `contract.source` at its digest |
| the commit is where claimed | `git merge-base --is-ancestor <head_sha> origin/<BASE>`          |
| tests pass at that SHA *(coordinator)* | clean worktree checkout + full run — pasted output is a hint     |
| the proof can fail          | revert/mutate on a sample, watch it go red                       |
| the review is fresh         | `pr.reviewed_sha == head_sha`                                    |
| the change is real on base  | a symbol from the unit is greppable on `origin/<BASE>`           |
| deployed == reviewed *(coordinator)* | (ship only) deployed revision equals the released SHA            |

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/negative-control.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/negative-control-light.jpg">
    <img src="../assets/diagrams/negative-control-light.jpg" alt="Head-to-head on the same gamed manifest that reports only AC-1 of a two-criterion spec: a self-scoring gate grades the worker's own list and returns GREEN; orca-fleet's verifier re-derives the criterion set from the frozen spec in a fresh session and returns RED, AC-2 not addressed; and for every fix the negative control reverts it and the proof must go RED" width="820">
  </picture>
</p>

A unit that fails any required check is not done — it returns to its state machine. When Orca's
provenance says "completed" but git disagrees, the unit is marked SUSPECT and treated as failed.
Git is truth; the ledger is its cache.

Two further guards keep the reviews honest: each manifest records its `reviewer_mode` (verify.py
checks it is a legal value), and a coordinator flags an "independent" review byte-identical to the
worker's own output — instructed isolation is named as the weaker guarantee it is; and reviewers
practice **blind-fix** — writing their own expected fix to disk before opening the candidate
diff, because anchoring on a handed artifact is cheaper than re-deriving the answer. At run
close, a sha256 inventory of every referenced artifact makes the evidence tamper-evident.

## Decision gates: mechanical, taste, one-way

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/decision-gates.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/decision-gates-light.jpg">
    <img src="../assets/diagrams/decision-gates-light.jpg" alt="Three decision lanes: mechanical flows straight through automatically, taste batches cards and continues, one-way stops at a vault door only a human can open" width="820">
  </picture>
</p>

Fleets hit hundreds of decisions per run. Sending every one to a human makes autonomy pointless;
sending none makes it dangerous. So every decision is classified **before** anyone answers
([`runtime/gate-classification.md`](../runtime/gate-classification.md)):

- **Mechanical** — one defensible answer exists (tooling with repo precedent, naming,
  retry-on-transient). The coordinator auto-resolves and writes an audit line: gate, class,
  answer, why.
- **Taste** — reasonable people could disagree, and it is reversible (API shape, copy,
  structure within spec). The coordinator picks the recommendation, batches the decision into a
  brief, and keeps working. You can veto later.
- **One-way** — hard or impossible to reverse, or out of authority: merge to default, deploy,
  rollback, deletion, spend, scope change, secret rotation. **Human, always.** Never
  auto-resolved, never defaulted on timeout.

Every dispatched unit also declares **lighting**: default `lit` (a human or build-blind reviewer
reads the change before it lands). `dark-eligible` is opt-in and only when the unit is Lane A
(reversible testnet/fixtures), the stop condition is a cheap unfakeable oracle (types / tests /
binding audit), and the unit is not on the irreversibility stop-list. Recording nothing means
`lit`.

Two refinements worth knowing. First, the *user-challenge* rule: when the fleet's analysis says
**your** stated direction is wrong, that is never auto-decided — your direction is the default,
and the fleet must argue its case, name its blind spots, and state the cost if it is wrong.
Second, escalation is honest about who is on the other end: an agent-to-agent `ask` is not a
human, and labeling one as human approval is forbidden. In unattended runs, unanswerable one-way
questions get parked and the run continues elsewhere or winds down.

## The merge train

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/merge-train.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/merge-train-light.jpg">
    <img src="../assets/diagrams/merge-train-light.jpg" alt="A train of PR cars on a single track entering the BASE station; the conductor inspects the lead car; one stale car is diverted to a dashed re-review side track" width="820">
  </picture>
</p>

Parallel workers opening PRs onto one integration BASE invites two failure modes: merge races
(PRs rebasing over each other) and stale evidence (merging a SHA the reviewer never saw). The
cure is boring and absolute ([`runtime/merge-serialization.md`](../runtime/merge-serialization.md)):

- **One conductor per BASE.** Two trains on one base is a race, not redundancy.
- **Arrival order.** No priority lanes without a human gate.
- **Freshness at the head of the queue.** The conductor checks the PR is open, targets BASE
  (never the default branch), and its head equals the reviewed SHA. Mismatch → bounce to
  re-review, requeue at the back.
- **Hot-file chains.** PRs touching the same mount-point file (route registry, DI wiring,
  migrations, barrels) build in parallel but merge as a chain, one at a time, as a union.
- **Ancestry verification, not grep.** A merge counts when
  `git merge-base --is-ancestor <mergeCommit> origin/<BASE>` says so.

## Attention budget (orchestration tax)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/attention-budget.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/attention-budget-light.jpg">
    <img src="../assets/diagrams/attention-budget-light.jpg" alt="Many worker terminals funnel toward a narrow neck where one human reviews; only three lanes pass the WIP gate while the rest queue; a single calm outflow is labeled merged" width="820">
  </picture>
</p>

Starting agents is cheap; closing the loop is not. Your judgment is the serial bottleneck, so
fleets scale to **verification capacity**, not the UI's spawn limit
([`runtime/attention-budget.md`](../runtime/attention-budget.md)). Default mutation waves keep
≤3 concurrent builders and about one build-blind reviewer per three builders. Isolated,
machine-verifiable work fans out; judgment-heavy work stays serial. Merge serialization is
consumer-side backpressure; the attention budget is producer-side — together they keep the
fleet from burying you under unreviewed diffs.

## Reviewed-SHA freshness

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/reviewed-sha-freshness.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/reviewed-sha-freshness-light.jpg">
    <img src="../assets/diagrams/reviewed-sha-freshness-light.jpg" alt="A commit carries a glowing reviewed seal; the branch advances one commit and the seal over the new head turns dashed red and void; a loop arrow returns for a fresh review" width="820">
  </picture>
</p>

The single most common way a fleet ships unreviewed code: a branch head that moved *after*
review. A conductor rebase, a review-bot autofix commit, a builder's late push — all of them void
the review, by rule ([`runtime/reviewed-sha-freshness.md`](../runtime/reviewed-sha-freshness.md)).
The merge step refuses on mismatch, and — the part people push back on until it saves them —
**"re-ran the gates green" is not a review.** Only a fresh build-blind review of the new head
restores freshness.

## Liveness, crash, resume

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/liveness-resume.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/liveness-resume-light.jpg">
    <img src="../assets/diagrams/liveness-resume-light.jpg" alt="A heartbeat line flatlines at a red X over a crashed terminal; below, the ledger document seeds a fresh coordinator terminal that reconnects to its workers" width="820">
  </picture>
</p>

Long runs die in boring ways: a worker hangs, a terminal is killed, the coordinator's machine
sleeps. The runtime tracks heartbeats and provenance in SQLite; the fleet supplies the reflexes
([`runtime/liveness-resume.md`](../runtime/liveness-resume.md)):

- **WATCH.** A dispatched task with no heartbeat past the window is stale. Respawn goes to a
  **fresh terminal** (re-dispatching to a used handle is a no-op), with an evidence line and a
  **reflection-before-retry** note first, and a bounded attempt count. Three failures — or two
  consecutive identical error signatures — → escalate or reassign, don't thrash.
- **The stuck-pending watchdog.** Task dependencies are not validated at creation, and a dep
  that *fails* (rather than completes) strands its children in `pending` forever — convergence
  detection only flags `blocked`. Every fleet watches for pending-with-unmet-deps explicitly.
- **RESUME.** A dead coordinator rebuilds from the ledger header + Orca provenance, scoped to
  its own run (runtime state is global; without scope, resume aborts). Every "completed" unit is
  cross-verified against git before being trusted; verified-merged work is never redone.

## Sandbox profiles

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/sandbox-profiles.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/sandbox-profiles-light.jpg">
    <img src="../assets/diagrams/sandbox-profiles-light.jpg" alt="Three containment vessels: an open glass dome labeled ro, a workbench box labeled rw, and a sealed chamber labeled danger on a detached disposable platform, pushing a git branch to safety before teardown" width="820">
  </picture>
</p>

Workers get the least privilege that does their job
([`runtime/sandbox-policy.md`](../runtime/sandbox-policy.md)):

| Profile  | Means                                     | Used for                          |
|----------|--------------------------------------------|-----------------------------------|
| `ro`     | read-only / plan mode                      | report-only work: reviews, audits |
| `rw`     | workspace-write                            | ordinary fix/build work           |
| `danger` | bypass approvals — **opt-in flag required**| exploit PoCs, destructive tests   |

`danger` never runs on your machine: its sanctioned home is a disposable per-workspace sandbox.
Work is harvested off the sandbox via `git push` to a work branch **before** teardown, and enters
BASE through the normal PR → review → merge-train pipeline like everything else. A lane whose
sandbox died before the push is a failed lane, not a shrug.

## Security boundaries and the response ladder

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/threat-boundaries.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/threat-boundaries-light.jpg">
    <img src="../assets/diagrams/threat-boundaries-light.jpg" alt="The four security boundaries from threat-model.md — sandbox with isolated worktree, ro/rw/danger profiles, PreToolUse deny-hook and v1.4.229 OS process/memory ceiling; network with hash-chained egress.py receipts; supply chain with runtime/pins.json, pin_review.py rug-pull audit, one pack per worker and guard_text.py trust envelope; identity and access with ed25519 dispatch-sign.py contract digest, human-only one-way gates and an independent SHA-bound verifier — beside the five-rung response ladder from steer, reduce and stop to revoke and fail-closed quarantine" width="820">
  </picture>
</p>

Prompt text is an optimization, never a security boundary. What keeps an autonomous fleet safe is
what the layers below the model make impossible or evident
([`runtime/threat-model.md`](../runtime/threat-model.md)):

- **1. Sandbox** — isolated git worktrees, `PROFILE=ro|rw|danger` tool gates, the `PreToolUse`
  deny-hook (`profile-gate.sh`), and `orca serve` OS-level process/memory ceilings
  (`ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX` at v1.4.229).
- **2. Network** — hash-chained egress receipts (`runtime/scripts/egress.py`); the deny-hook
  refuses unreceipted `gh` write calls (`pr create`, `issue close`, `api -X POST`) and run close
  anchors the chain head in the tamper-evident inventory.
- **3. Supply chain** — exact upstream commit pins in `runtime/pins.json` with line-by-line
  rug-pull reviews enforced by `runtime/scripts/pin_review.py`, one router pack per worker, and the
  `runtime/scripts/guard_text.py` untrusted-text fence.
- **4. Identity & access** — Ed25519-signed dispatch envelopes (`runtime/scripts/dispatch-sign.py`)
  so a worker cannot rewrite its own contract digest, human-only one-way gates, and an independent
  SHA-bound verifier (`runtime/scripts/verify.py`).

When a signal fires across any boundary, the coordinator escalates through the five-rung **response
ladder**: **1. Steer** (in-session deny-hook feedback) → **2. Reduce** (park the unit and
re-dispatch `ro`) → **3. Stop** (kill the worker terminal and block dependents) → **4. Revoke**
(rotate exposed credentials, one-way human gate) → **5. Quarantine** (record the component in
`runtime/quarantine.json`, enforced fail-closed across preflight, validation, and hooks).

## Hosted trackers and the trust envelope

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/tracker-enumeration.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/tracker-enumeration-light.jpg">
    <img src="../assets/diagrams/tracker-enumeration-light.jpg" alt="Four-stage pipeline for hosted trackers: GitHub Issues/PRs, Linear via orca linear, and Jira via orca jira at v1.4.229 enter the T0 twin-query denominator paged until truncated is false and reconciled across two independent workers, pass through the guard_text.py trust fence so ticket text remains data rather than authority, and close with single-attempt writeId or read-back plus orca reference add/find backed by a verified merge SHA" width="820">
  </picture>
</p>

Trackers feed `clean-sweep`, `absorb-it`, and `oss-contribute`, and in Orca v1.4.229 three hosted
surfaces speak structured JSON natively: GitHub (`gh issue/pr list --json`), Linear
(`orca linear list --workspace <id> --json`), and Jira (`orca jira list` / `orca jira search <jql>
--site <id> --json`). Every tracker run enforces three invariants
([`playbooks/linear-enumeration.md`](../playbooks/linear-enumeration.md)):

- **T0 twin-query denominator.** Record `T0` before the first query, page until `truncated: false`
  (or `count < limit` on bounded JQL), and reconcile two independent workers on the frozen query
  before dispatching any build wave.
- **Untrusted-text fence (`guard_text.py`).** Ticket titles, bodies, and comments are attacker-writable
  data, never authority. Before a worker sees tracker text, `guard_text.py` normalizes Unicode
  (`NFKC` + format-char stripping), defuses forged delimiter banners, and flags prompt-injection
  shapes (`[INJECTION-PATTERN]`).
- **Single-attempt closure & cross-references.** Status transitions and closing comments replay a
  stored `writeId` at most once (or read back current state before retrying) and attach PR/branch
  links via `orca reference add`, while actual completion is proved only by the merged SHA in the
  unit's evidence manifest.

## One router per worker

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/one-router-per-worker.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/one-router-per-worker-light.jpg">
    <img src="../assets/diagrams/one-router-per-worker-light.jpg" alt="Three worker desks each hold exactly one glowing playbook; a fourth desk with two overlapping playbooks is struck through with a red X" width="820">
  </picture>
</p>

Missions draw worker methodology from three upstream packs, and each pack ships its own
router/meta-skill. Co-mount two and they fight: clashing command names, competing routing,
conflicting philosophies (one pack folds refactoring into the TDD loop, another puts it in
review). The rule is absolute: **a worker loads exactly one pack's playbooks.** Cross-pack
composition happens at the mission level — one worker runs Matt-style triage while another runs
Addy-style security — never inside a single worker's context.

## Chaining missions

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/mission-chaining.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/mission-chaining-light.jpg">
    <img src="../assets/diagrams/mission-chaining-light.jpg" alt="A chain of mission links joined by gate valves; the first two glow with checkmarks; the gate before the dim third link is closed with a red bar and requires a human" width="820">
  </picture>
</p>

"Make this repo production-ready" is not one mission — it is harden-it, then prove-it, then
ship-it. Chains are deliberately minimal ([`runtime/mission-chaining.md`](../runtime/mission-chaining.md)):
sequential only, declared up front with the terminal states allowed to proceed at each link. The
gate between missions is the previous mission's **verified** terminal state — an audit gates, it
never "continues anyway"; a degraded terminal (`HARDENED-WITH-OPEN-ITEMS`, `COVERED-WITH-PARKED`)
stops the chain, and advancing past it is a one-way human gate. Each link is a full run with its
own preflight and BASE, and mission N's parked and noticed-but-not-touched items seed mission
N+1's enumeration as findings to triage. A chain that stops early is a correct outcome.

## Proof status

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/proof-ladder.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/proof-ladder-light.jpg">
    <img src="../assets/diagrams/proof-ladder-light.jpg" alt="The proof ladder: doctrine-only, then self-run, then external-run; advancing needs a run report that binds, with a RUN header, a manifest in the run's own directory and an inventory that re-hashes at the named commit; the live state is the archive at docs/runs/README.md, which names each mission's tier as its evidence lands" width="820">
  </picture>
</p>

Every mission declares how proven it is — `doctrine-only`, `self-run`, or `external-run` — in
validator-enforced frontmatter, and cannot advance without a linked run report on disk. This is
the inherited lesson from this catalog's failed predecessor, which shipped twelve missions with
two proven: doctrine is allowed to encode hard-won lessons, but it is never allowed to dress up
as evidence.

The three tiers, defined once here (other pages link this section):

| Tier | Means | Does NOT mean |
|---|---|---|
| `doctrine-only` | the protocol is written and validated; no run report binds to it | the mission never ran — some ran without retaining artifacts here |
| `self-run` | a run report binds, and the run's **target** was this catalog (orca-fleet itself) | an outside party ran it |
| `external-run` | a run report binds, and the run's **target** was a repository other than this catalog | an outside party ran it — the tier names the target, not the runner |

Who ran it is a separate fact, recorded in the report's runner row: both of today's
`external-run` tiers (`ship-it` on ravidsrk/mdtoc, `review-it` on stablyai/orca) were
maintainer-run. No tier yet rests on a run by someone outside the project; the
[call for runs](call-for-runs.md) asks for exactly that.

Be precise about what the gate buys, because it is weaker than "re-derives" would imply and
[`run_report.py`](../runtime/scripts/run_report.py) says so in its own docstring: **it hashes, it
does not re-run the verifier.** The [2026-09-11 review](reviews/2026-09-11-review.md) fabricated a `map-it`
self-run — seven files, one commit, under fifteen minutes — that reported "bound" and passed
`validate.py`, `proof_status.py --check` and the whole suite, because files a worker writes and
commits hash true at the commit that contains them. What the gate really refuses is a tier claimed
on a report whose artifacts were never retained, re-pointed at another mission, or pinned to a
commit where the bytes differ. It does not refuse a tier whose artifacts were manufactured, and
re-running the verifier afterwards would not fix that: the authorities that made the original
verdict — the coordinator's out-of-band contract, a live GitHub review lookup, the worktree as it
stood — are gone. Closing this needs a leg the worker cannot type at all: a coordinator-signed
verifier transcript checked against a committed key
([#281](https://github.com/ravidsrk/orca-fleet/issues/281)), on top of making the tier cost an
actual run ([#286](https://github.com/ravidsrk/orca-fleet/issues/286)).

The live state is the [run archive](runs/): it names each mission's tier as its evidence
lands and records every run that really happened, saying per run whether and why it binds. Tiers
are earned only through the binding gate, even when that makes the proven count go *down* as the
mechanism gets stronger — which is the mechanism working. The predecessor shipped twelve missions
with two proven and paid for it, and a tier whose artifacts are gone is the same claim in better
packaging.

## Autonomy

Every mission's `metadata:` block carries `autonomy:`, checked by the validator against Addy Osmani's
L0–L5 ladder ("Agentic Autonomy Levels", addyo.substack.com, 2026-07-03). The ladder is about
*structure*, not about what the agents are allowed to touch. In the source's own terms: L3,
goal-driven autonomy, is one agent looping until a measurable stop condition is met; L4,
parallel delegation, is many agents each working an isolated slice of the task; L5,
managed-by-exception orchestration, is a manager that wakes on triggers, dispatches workers,
verifies their output, retries, and escalates.

Derived from those definitions, every mission in this catalog is **L4 by structure**: one
coordinator, parallel workers in isolated worktrees, a verifier over their output. That includes
the read-only and planning missions — `review-it` dispatches its axis reviewers in parallel,
`map-it` its research workers, `root-cause` its hypothesis falsifiers, `attest-it` its evidence
workers — because a human owning the verdict or the plan is a **gate class** (a one-way door,
above), not a lower rung on the ladder. The source defines no "who owns the verdict" axis, and
this catalog does not invent one in its name. A scheduled, unattended run
([`runtime/mission-scheduling.md`](../runtime/mission-scheduling.md)) is the L5 shape — a trigger
wakes the coordinator, which dispatches, verifies, retries within bounds, and escalates the rest
to the human-owed queue — but the mission's declared level stays L4: the level describes the
mission's structure, and scheduling is a way of invoking it.

## Activation load

Every mission is several times the 5,000-token community recommendation, on purpose: the
runtime policies are whole contracts, and a coordinator that reads half of a merge-ordering rule
improvises the other half. The cost is real, and each guide states it on its Activation-load
line: roughly a sixth of a 200k-token context is spent before the first dispatch. Two
consequences for you: start a mission in a fresh session, and expect the coordinator's own
context to compact during a long run, which is why the ledger, not the scrollback, is its
memory. The measurement, the cap and why it only ratchets down are in
[ARCHITECTURE.md](../ARCHITECTURE.md#instruction-budget).

## The mission-identity test

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/mission-identity.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/mission-identity-light.jpg">
    <img src="../assets/diagrams/mission-identity-light.jpg" alt="The six-point mission-identity test: unit of work, per-unit state machine, convergence proof, ordering and isolation, parking and failure semantics, and the oracle; audit findings, tracker issues and doc claims are one mission, clean-sweep, while a perf breach is a different proof and therefore a different mission, speed-it" width="820">
  </picture>
</p>

The catalog stays deliberately small because of a bright-line test. Two workflows are the **same
mission** only if they share *all six*:

1. the same unit of work,
2. the same per-unit state machine,
3. the same convergence proof,
4. the same ordering and isolation constraints,
5. the same parking / failure semantics,
6. the same oracle — the authoritative source the proof binds to. Two workflows that differ
   *only* in oracle are one mission with an `oracle=` source; they are different missions only
   when the oracle changes the proof's shape or the parking classes.

"Inventory → fix → repeat" is not enough — almost every maintenance process paraphrases that
way. Audit findings, tracker issues, and false doc-claims all close through the same
per-finding pipeline with the same proof against the same repo-suite oracle, so they are one
mission (`clean-sweep`). A perf breach is *not* a finding: done is a statistical budget over
journeys, measurements are noisy, and fixes interact — different proof, different mission
(`speed-it`). Contributing those same fixes to a repo you do *not* control is also its own mission
(`oss-contribute`): the convergence proof is a PR open and reviewed rather than a merged SHA, the
state machine adds upstream-PR overlap discovery and drops the merge step, and
`awaiting-maintainer-merge` is a normal terminal — three of the six differ from `clean-sweep`.
The oracle point is what keeps `access-it` (a rule engine with a ceiling that creates a human-AT
park class), `field-test-it` (the target itself, in tiers), and `pin-it` (an external control
plane whose claims can be refuted, not just closed) their own missions; the argument for each is
in [ARCHITECTURE.md](../ARCHITECTURE.md), and the candidates that failed the test are ledgered
in [docs/research/REJECTED.md](research/REJECTED.md). When you are tempted to add a mission, run
this test first; when you are tempted to add a *mode* to a mission, run it twice.

---

Deep dives: every mission has its own guide under [docs/missions/](missions/), a real run is
walked ledger-line by ledger-line in [Anatomy of a run](guides/anatomy-of-a-run.md), dated
research snapshots that informed adoption decisions live in [docs/research/](research/), and
the agent-facing sources are [`skills/`](../skills/), [`playbooks/`](../playbooks/), and
[`runtime/`](../runtime/).
