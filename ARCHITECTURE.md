# orca-fleet architecture

A fleet is an **outcome**, not an ingredient. Missions are named for what they achieve
("ship it", "close every issue", "find the root cause"), never for the pack whose technique
a worker happens to run. This repo has no `matt-*` or `gstack-*` skills. The upstream packs
(mattpocock/skills, garrytan/gstack, addyosmani/agent-skills) are sources of *recipes* that
missions compose; the Orca runtime is the substrate every mission rides.

## Three layers, strictly separated

```
MISSIONS   (skills/, discoverable)     ← the only user-facing skills. One outcome each.
   │  compose, by reference, →
PLAYBOOKS  (playbooks/, callable)       ← reusable phase protocols. NOT auto-triggering skills.
   │  run on, →
RUNTIME    (runtime/, invisible)        ← Orca primitives + policies. Called, not discovered.
```

> Missions are discoverable. Playbooks are callable. Runtime mechanisms are invisible unless
> directly administered.

Publishing playbooks or runtime mechanisms as auto-triggering skills would recreate the exact
routing collisions and ingredient-shaped entry points this repo exists to remove. So:

- **Missions** are `skills/<name>/SKILL.md` — the discoverable catalog. Each is one outcome
  with a distinct state machine and an evidence-based definition of done.
- **Playbooks** are `playbooks/<name>.md` — plain protocol docs a mission references by bare
  name (never a path) and injects into worker task specs. They are versioned, executable
  protocols with checkable completion criteria, never attribution summaries of "best of X + Y".
  One consuming mission is enough when the doc is a phase protocol a worker TASK injects
  (`data-migration`, `instrument`); mission prose moved out to dodge the body cap is not.
- **Runtime** is `runtime/*.md` policies + `runtime/scripts/` shared tooling — the Orca
  dispatch/gate/merge/liveness/sandbox mechanics. Missions call these; users don't invoke them.

## What makes a mission a mission (not a mode of another)

Two workflows are the **same mission** only if they share ALL six:

1. the same unit of work,
2. the same per-unit state machine,
3. the same convergence proof (definition of done),
4. the same ordering and isolation constraints,
5. the same parking / failure semantics,
6. the same **oracle** — the authoritative source a unit's proof binds to (the repo's suite, a
   rule engine over a frozen surface, a ledgered device session, an installed binary). One rule
   governs it: two workflows that differ ONLY in oracle are one mission with an `oracle=`
   source, and they differ as missions only when the oracle changes the convergence proof's
   shape or the parking classes.

"Inventory → fix → repeat" is not enough — almost every maintenance process paraphrases that
way. By this test, closing audit findings, tracker issues, and false doc-claims are one mission
(`clean-sweep`) — they share the convergence proof SHAPE (full re-enumeration finds zero open)
and the repo-suite oracle (a finding is closed when its covering test goes RED on revert), even
though each source materializes the denominator differently; but security hardening, perf
budgeting, dependency modernization, test-debt proving, and flake eradication are NOT — their
denominators and convergence proofs differ, so each is its own mission.

Point six is the decision docs/reviews/2026-09-10-review.md §6 asked for and the 2026-09-10 audit §4.3 records: the
oracle is an identity point, no mission is deleted, and the three missions it argues for are
argued here, not assumed.

- `access-it`: the oracle is a deterministic rule engine (axe-core) over a frozen surface, and
  it is incomplete by construction — it sees roughly a third of WCAG. That ceiling creates a
  park class no repo-suite finding has: `CONFORMANT-WITH-MANUAL-PARKED`, owed to a human
  assistive-technology reviewer as a standing terminal, not an exception. The oracle changes the
  parking semantics, so this is its own mission — and any further deterministic rule catalog
  (a design-rule pre-pass, say) is an `oracle=` source inside it, not a mission.
- `field-test-it`: the oracle is the target itself — a ledgered device session, never a desktop
  pass — and the convergence proof is re-verification *on that target* at `head_sha` with an
  on-target revert control. That makes it the oracle-tiered "prove it on the target" mission:
  `DEVICE` / `EMULATOR` / `BROWSER` / `DESKTOP` / `CLEAN-ENV` are tiers of one oracle family
  that share the proof shape (reproduce on the target → fix → re-verify on the target → revert
  reproduces), so driven-browser, desktop-accessibility-tree, and fresh-sandbox proofs are
  tiers here, not missions of their own.
- `pin-it`: the oracle is an external control plane — `orca skills get` and the installed
  binary — that the repo neither owns nor can mutate, so the proof shape inverts: a unit
  converges by receipting a claim CURRENT *or by refuting it*, and the refutation archive is a
  terminal class `clean-sweep` lacks (a refuted doctrine claim is removed with its receipt
  kept, never "closed"). Different oracle, different proof shape and parking; its own mission.
  Measured rather than asserted since #288: `pin-it` and `clean-sweep` share ZERO near points of
  the six (mean similarity 0.015), so they do not differ only in oracle — they differ in all of it.
  The 2026-09-11 review argued `pin-it` folds into `clean-sweep` as an `oracle=` source; that
  finding is withdrawn, and the naming objection with it — `PINNED` / `PINNED-WITH-PARKED` are
  terminal states the repository reaches, the same shape as `DRY`, not the artifact being edited.

## The definition of done is an evidence protocol, not trace-grading

A coordinator does not hold its workers' terminal traces, and a trace proves an action was
*attempted*, not that the resulting state is *correct* (an agent can run the right-looking
commands against the wrong SHA). So completion is never graded on narration or trace.

Every unit of work emits a **SHA-bound evidence manifest** (see
[`runtime/evidence-manifest.md`](runtime/evidence-manifest.md)): base SHA → head SHA, the exact
acceptance criteria addressed, commands run with exit codes, artifact paths (logs, reports,
screenshots, benchmarks), the negative-control result, the intent packet (`goal` · `ruled_out` ·
`why`) on mutation units, `lighting` (`lit` or `dark-eligible`), PR + reviewed SHA, and any
parked items.
An **independent verifier** then checks facts against authoritative state: does the commit exist
on the intended base, does mutating the fix break the proof, does an APPROVED GitHub review sit at
head — while the coordinator re-runs the suite in a clean env and confirms deploy == reviewed. The Orca provenance
DB records the lifecycle and evidence references; traces are for forensic audit, never the
completion oracle.

## The operational details ARE the product

`clean-sweep` and `spec-to-ship` worked because of their ugly operational specifics, not despite
them. These are preserved as runtime policies, not abstracted away:

- Orca DAG semantics for CLI fleets (global DB, handle-scoped runs, deps-not-parent_id, real vs
  fictional message types, gate lifecycle ≠ blocking) — `runtime/orca-dag-semantics.md`
- Ledger boolean gates, `CODE_CLOSED`/`VERIFY_AT_SCALE`, DECISIONS.md, CONTEXT HANDOFF —
  `runtime/ledger-contract.md`
- wrong-base detection (BASE ≠ default, canonical-ref comparison) — `runtime/dispatch-lifecycle.md`
- coordinator inbox mechanics + worktree retirement (batched Delivery + ack, read-marking,
  broadcast-only groups, verified teardown) — `runtime/dispatch-lifecycle.md`
- reviewed-SHA freshness (a rebase voids the review unless the content tree is unchanged) — `runtime/reviewed-sha-freshness.md`
- ledger recovery / crash-resume from provenance, cross-run anti-inflation — `runtime/liveness-resume.md`
- worker supervision (per-dispatch budgets, stuck-but-alive ladder, transcribe-at-delivery, fenced-coordinator re-bind) — `runtime/worker-supervision.md`
- bot-autofix non-convergence (Cursor BugBot Autofix loops) — `runtime/dispatch-lifecycle.md`
- bounded review loops, hot-file ownership, merge serialization — `runtime/merge-serialization.md`
- post-merge evidence closure by the coordinator at the merged tip — `runtime/conductor-close.md`
- attention budget / orchestration tax (scale to review rate, not spawn UI) —
  `runtime/attention-budget.md`
- promotion semantics (human gate; merge ≠ deploy) and per-unit lighting (`lit` default;
  `dark-eligible` only Lane A + unfakeable oracle) — `runtime/gate-classification.md`
- gated sequential chains (an audit gates, it never always-flows) — `runtime/mission-chaining.md`
- scheduled unattended runs via `orca automations` (only missions whose value lands before a
  one-way gate schedule cleanly) — `runtime/mission-scheduling.md`
- least-privilege worker profiles (`ro`/`rw`/`danger`; `danger` only in a disposable sandbox,
  work harvested via git push before teardown) — `runtime/sandbox-policy.md`
- the Orca pin record (which upstream build the doctrine was witnessed against, re-pin
  cadence, owner, next trigger) — `runtime/orca-pin.md`
- trust assumptions and the four security boundaries (sandbox, network, supply chain,
  identity/access), each graded with its residue, plus the graded response ladder —
  `runtime/threat-model.md`

## Proof over doctrine

This repo's predecessor (ravidsrk/autonomous-fleet) died of doctrine outrunning evidence: twelve
missions with two proven, a portable substrate with zero field hours, and ~42K tokens of mandatory
instruction surface. Two structural guards inherit that lesson:

- **Proof status.** Every mission's `metadata:` block carries `proof:` — `doctrine-only`,
  `self-run`, or `external-run`. Advancing past doctrine-only requires `proof_evidence:` at a run
  report that exists on disk; `scripts/validate.py` enforces both. A mission is never presented
  as more proven than its evidence. `self-run` and `external-run` name the run's TARGET (this
  catalog vs. any other repository), never the runner: `ship-it`'s `external-run` was
  maintainer-run on mdtoc. The one definition lives in
  [docs/concepts.md#proof-status](docs/concepts.md#proof-status).
- **Runtime evidence level.** Runtime policies are doctrine (mechanism) by default; a policy that
  makes an EMPIRICAL claim carries an explicit `Evidence level:` (ASSERTED / measured) —
  `attention-budget.md` is the exemplar of the Evidence-level rule (its own level is ASSERTED
  until the WIP-curve runs land). Each mission guide surfaces the mission's `proof:` tier beside
  its autonomy, so a doctrine-only, never-run mission never reads as field-proven.
- **Instruction budget.** Mission body ≤ 110 + frontmatter ≤ 34 lines, playbooks ≤ 90, runtime
  policies ≤ 160, enforced
  by the validator — plus a per-file **byte budget** (240 B × the line cap) so instruction surface
  packed into a few very long lines cannot beat the line count. Raising a cap is a deliberate,
  reasoned edit — never drift.

## Governance is uniform and below the model

- Every decision is classified **mechanical / taste / one-way** and resolved per
  `runtime/gate-classification.md`. One-way doors always override any auto-decide preference.
- Autonomy tracks the session kind: spawned → auto-pick recommended; headless → block on the
  unanswerable; interactive → prose brief. A fleet never fakes a human answer.
- One router per worker: a worker TASK loads exactly one upstream pack's playbooks (they fight
  when co-mounted). Missions compose across packs at the mission level, one pack per worker.

## Instruction budget

Three caps, all in `scripts/validate.py`, all enforced at CI:

| What | Cap | Why |
|---|---|---|
| mission **body** lines | 110 | the instruction surface a coordinator reads as protocol |
| mission **frontmatter** lines | 34 | declarations, priced apart so a machine-readable claim never costs a protocol line |
| mission **activation load** | 34,000 tokens | the SKILL.md *plus every doc its Composes/rides clause makes mandatory* |

The first two bound each file. The third is the number that actually matters, and until issue #276
nothing bounded it. Measured (bytes/4) the heaviest mission was `ship-it` at **~39,600 tokens**; the
predecessor died at ~42,000.

The heaviest missions carry a **DEFERRED READS** paragraph outside their Composes/rides clause,
naming each phase-scoped doc and when to load it — `ship-it` came down from 39,600, `oss-contribute`
from 37,400, `clean-sweep` from 36,500. Only the clause counts as load, so a deferral is a real
change in what a coordinator reads at activation, not a relabelling. Where they stand today:

<!-- BEGIN GENERATED: activation-load — scripts/gen-badges.py -->

| Mission | Activation load | Headroom to the cap |
|---|---|---|
| `ship-it` | ~33,700 | ~300 |
| `harden-it` | ~33,400 | ~600 |
| `modernize-it` | ~33,100 | ~900 |

The cap is **34,000**. The lightest mission, `offload-it`, is ~15,100, so the whole catalog sits in a ~18,600-token band.
<!-- END GENERATED: activation-load -->

That table is generated by `scripts/gen-badges.py` and its freshness is a CI gate. It used to be
typed by hand, and drifted 150–280 tokens within a day of publication (#303) — then drifted again
during the work that fixed it, by which point the ORDERING had changed too. A number a human
retypes is a claim with no mechanism, which is the shape this document exists to refuse.

### The 5,000-token recommendation is not a target here

agentskills.io recommends under 5,000 tokens per activated skill, with references loaded on demand
behind an explicit "read X when Y" cue. **This catalog does not meet that and is not pursuing it.**
Every mission is several times it (the generated table carries the figures; no multiple is retyped
here, #303). The cost is deliberate: a coordinator that rides `merge-serialization` needs the whole
ordering rule, not a pointer — the failure doctrine prevents is a fleet improvising the half it did
not read. Deferral is honest accounting only for ACTIVATION; a full run still reads the deferred docs.

Meeting the recommendation would mean restructuring each runtime policy into a ~30-line contract
plus an on-demand reference — a real option, not attempted here. Until then the 34,000 cap is a
ratchet set just above the measured maximum, lowered only by deferring more reads, never raised.
Each mission's own number is published in its guide (`docs/missions/<name>.md`, same script).

## Layout

The directory map lives once, in [README.md#repository-layout](README.md#repository-layout).

## See also

- [docs/platform-ride.md](docs/platform-ride.md) — riding native Claude Code / Agent SDK / MCP
  primitives; dated absorption-risk register.
- [docs/compliance-provenance.md](docs/compliance-provenance.md) — the manifest's `provenance`
  block mapped to EU AI Act Art-12/50 (the `attest-it` prerequisite).
- [docs/research/REJECTED.md](docs/research/REJECTED.md) — mission candidates rejected under the
  identity test, so none is re-argued from scratch.
- [docs/distribution.md](docs/distribution.md) — discoverability, install paths, submission checklist.
- [docs/verify-gate.md](docs/verify-gate.md) — `verify.py` as a fail-closed `Stop`/`TaskCompleted`
  gate, its fallbacks, and the signed-dispatch record (#135; the native hook stays advisory).
- [demo/negative-control/](demo/negative-control/README.md) — a self-scoring gate GREEN on a
  scope-shrink trap while `verify.py` goes RED.
- [bench/vf-bench/](bench/vf-bench/README.md) — a benchmark of verifier soundness (false-done rate).
