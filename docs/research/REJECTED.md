# Rejected mission candidates

> **Dated snapshot (2026-09-10), standing ledger.** Every mission candidate that failed the
> mission-identity test ([ARCHITECTURE.md](../../ARCHITECTURE.md) — six points, the oracle being
> the sixth), gathered from the dated research docs so a candidate is never re-proposed without
> the prior argument in view. Append a row when a candidate is rejected; do not re-argue a row
> without a new fact. Sources: the 2026-09-10 deep audit §4.4, the 2026-08-28 forward roadmap,
> the 2026-08-16 delta plan, the 2026-07-15 gap analysis.

The test is bright-line on purpose. "Rejected as" names the shape the candidate actually is — a
source of an existing mission, a playbook, a runtime edit, operator tooling — so the value is
kept somewhere even when the mission is not.

| Candidate | Source | Rejected as | Reason | Date |
|---|---|---|---|---|
| `retire-it` (deprecate → migrate consumers → zero usage → remove) | addyosmani | mission-shaped but telemetry-bound | every proof depends on production usage counters; `-WITH-PARKED` is the normal terminal; single-surface sunsets are a clean-sweep finding; keep as a `migrate-it` tail | 2026-09-10 |
| `erase-it` (personal-data inventory, purpose, retention, export/delete proven) | addyosmani | attest-it with a GDPR catalog + clean-sweep via deferral carry | needs prod-like data plumbing and a legal owner per run; the privacy lens is the cheaper first move | 2026-09-10 |
| `sandbox-it` (danger lanes provably created, used, harvested, destroyed) | orca | runtime policy + script, not a user outcome | "destroy what you created" is hygiene; becomes a `sandbox_lane` script under `sandbox-policy.md` (#269) | 2026-09-10 |
| `hand-off-it` (fault injection against the fleet: kill the coordinator, adopt the Run, zero re-done work) | orca | `bench/` / `tests/` territory | tests orca-fleet, not the user's repo; its value is a `proof:` tier for `liveness-resume.md`, which a pin-it run's probes can deliver | 2026-09-10 |
| `verify-on-target` (one change proven on N hosts via `--on`) | orca | CI matrix does it cheaper | value only where a host cannot be a CI runner; federation is the youngest Orca surface | 2026-09-10 |
| `name-it` (one name per concept; glossary + rename reconcile + avoid-list lint) | mattpocock | floor-it lint dimension + decide-and-freeze ADR rule | nearly all HITL; a cosmetic oracle drives rename churn | 2026-09-10 |
| `orient-it` (a stranger can navigate: probe suite of cold `ro` sessions, no-op test per steering line) | mattpocock | compound-learn + re-probe | the oracle is an LLM run and never `dark-eligible`; WRITE is where damage happens | 2026-09-10 |
| `unblock-it` (the human-owed queue packaged as wizards/questionnaires and verified complete) | mattpocock | `human-handoff` playbook | mostly an artifact generator; the verification half is item-specific; pointless unattended | 2026-09-10 |
| `automate-it` (recurring loop specified, installed via `orca automations`, first-fire observed) | mattpocock, orca | `mission-scheduling.md` edit | most loops are missions already; collapses to one CLI line plus `--precheck` | 2026-09-10 |
| `record-it` (ADR currency) | mattpocock, addyosmani | `record-decision` playbook | the "why" lives in human memory; DETECT has no oracle | 2026-09-10 |
| `contract-it` (public-interface contract sweep + idempotency) | addyosmani | prove-it with surface = public interfaces; api-contract lens addition | passes only point 1, weakly | 2026-09-10 |
| `watch-it` (standalone canary) | gstack | publishing `observe.md` as a skill | ARCHITECTURE.md's three-layer rule forbids exactly that | 2026-09-10 |
| `vet-it` (external-contributor security sweep) | gstack | harden-it source | same loop; "commits by external authors since date" is an enumeration input | 2026-09-10 |
| `plan-review` / `challenge-it` (CEO/eng/design/DX lenses, autoplan) | gstack | playbook composed by map-it and ship-it | decisions are map-it's terminal already | 2026-09-10 |
| `retro-it` / `score-it` / `health` | gstack | operator tooling | no finite denominator; composite scores that redistribute weight over missing tools are the vacuous-gate class floor-it forbids | 2026-09-10 |
| `drive-it` (web journeys driven in a real browser) | gstack | field-test-it oracle tier `BROWSER` + `browser-drive` playbook | same shape as field-test-it; differs only in oracle and lane parallelism | 2026-09-10 |
| `screen-prove-it` (desktop app through `orca computer`) | orca | field-test-it oracle tier `DESKTOP` | same shape with the OS accessibility tree as oracle | 2026-09-10 |
| `onboard-it` (getting-started executed on a clean environment per persona, TTHW budget) | gstack, addyosmani | field-test-it oracle tier `CLEAN-ENV` | same shape; oracle = fresh sandbox execution; budget from speed-it's metric contract | 2026-09-10 |
| `polish-it` (design-rule catalog + deterministic pre-pass) | gstack | access-it `oracle=` source (design catalog beside axe) | deterministic rule oracle on a frozen surface, taste parked to a human — access-it's shape | 2026-09-10 |
| `triage-it` (tracker tickets classified and stated without fixing) | mattpocock, orca | clean-sweep `--report-only` lane + `triage-state` / `linear-enumeration` playbooks | clean-sweep source=tracker minus code and PRs — the review-it/ship-it margin | 2026-09-10 |
| `stabilize-it` / incident-response | 2026-08-28 roadmap | belongs to SRE agents; `root-cause` owns the repo-scoped slice | telemetry substrate, not git; a prod-revert negative control is unsafe | 2026-08-28 |
| `docs-drift` | 2026-08-28 roadmap | mode of `clean-sweep` (false doc-claims source) | same unit, pipeline, proof, and oracle as a doc-claim finding | 2026-08-28 |
| `upgrade-it` | 2026-08-28 roadmap | mode of `modernize-it` | same expand/migrate/contract unit and proof | 2026-08-28 |
| `api-compat` | 2026-08-28 roadmap | mode of `review-it` (api-contract lens) | a lens on a SHA-bound verdict, not a new proof shape | 2026-08-28 |
| `patch-it` | 2026-08-28 roadmap | fold into `harden-it` with an SCA-frozen denominator | same audit → fix → re-attack loop; the SCA feed is an enumeration source | 2026-08-28 |
| `localize-it` | 2026-08-28 roadmap | not a mission | translation correctness is not git-verifiable — no unfakeable oracle | 2026-08-28 |
| `factory-it` / `loop-it` / `ralph-it` | 2026-08-16 delta plan | not a mission — mission-identity test fails | a loop is an ingredient or a mode, not an outcome with its own proof | 2026-08-16 |
| `orchestrate-it` / `factory-it` / `ralph-it` | 2026-07-15 gap analysis | not a mission — ingredients or modes | naming the technique instead of the outcome is the ingredient-shaped entry point this catalog exists to remove | 2026-07-15 |
| `poteto-mode` (a second router over every playbook) | pstack 0.15.20 | not a mission — ingredient | AGENTS.md already routes intent to one outcome; co-mounting every playbook in one worker is the pack-router fight the one-pack rule exists to prevent | 2026-10-12 |
| `correct-it` | pstack `/correct` | `encode-lesson` playbook, composed by floor-it, pointed at from compound-learn | the oracle is still "a check goes RED on a specimen"; a repeated class is a reflect output, not a new denominator | 2026-10-12 |
| `hillclimb-it` | pstack hillclimb | mode of speed-it | one metric, before/after, keep-or-revert is speed-it's loop; a target instead of a budget does not change the oracle | 2026-10-12 |
| `swarm-it` / `arena-it` | pstack | dispatch ingredient | parallelism and multi-model panels are runtime, not an outcome | 2026-10-12 |
| `autopilot-it` (land the stack even if CI flakes) | pstack autopilot-full / shipping | ship-it and absorb-it, and a refusal | a green-or-flaky merge contradicts reviewed-sha freshness and the unanswered-thread rule | 2026-10-12 |
| `show-work-it` | pstack show-me-your-work | ledger-contract + evidence-manifest | a TSV the author writes is a weaker oracle than a SHA-bound manifest an independent verifier re-derives | 2026-10-12 |
| `verify-skill-it` | pstack create-verification-skill | runtime-prove Part B + field-test-it | a generated project-local skill is a harness shape; driving the real entry point is already the proof | 2026-10-12 |
| `blast-it` | pstack blast-radius | one sentence in risk-review, not a mission | "the one safety fact is unproven until a run shows it" is a clearance rule on the existing lens; it does not change review-it's oracle | 2026-10-12 |
| `eval-it` (blinded A/B of a skill edit) | pstack eval playbook | tests/ and evals/, not a user outcome | same shape as the rejected fault-injection candidate: it tests the fleet, not the user's repo | 2026-10-12 |
| `visual-parity-it` | pstack visual-parity | field-test-it oracle tier, not added | reproduce on a target, fix, re-verify, revert — the proof shape is field-test-it's; a pixel oracle would be a tier, and no tier was added in this pass | 2026-10-12 |
| `chief-of-staff` (long-running single-session subagent/schedule coordinator) | mattpocock 49dd158 (`skills/in-progress/chief-of-staff`) | `runtime/mission-chaining.md` + `runtime/mission-scheduling.md`, not a mission | open-ended session with no finite denominator, no per-unit state machine, and no SHA-bound evidence manifest | 2026-10-17 |

The candidates that *passed* on 2026-09-10 (`migrate-it`, `oncall-it`, `absorb-it`,
`document-it`) are argued in the
[deep audit §4.1](2026-09-10-upstream-deep-audit-and-mission-proposals.md). All four **landed on
2026-09-10** and are in the catalog; recorded here so the ledger stays whole, as its own rule asks
(#289). A rejection ledger that only records rejections is half a ledger — the admissions are the
half that shows the bar moved.
