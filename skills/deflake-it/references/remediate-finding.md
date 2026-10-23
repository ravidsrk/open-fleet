# Playbook — remediate-finding  (the per-finding fix loop; shared by clean-sweep + campaigns)

Recipe: Matt `triage` (verify a finding before fixing it) on the fleet's own PR-per-finding closure.
The unit is ONE confirmed finding. Same loop whether the finding came from an audit, a tracker issue,
a security lens, a perf breach, or a flaky test — the mission supplies the finding SOURCE and the
"clean" contract; this playbook supplies the closure pipeline.

## Per-finding pipeline (PR-per-finding)

1. **Verify the finding is real BEFORE spending fix effort** (Matt triage): reproduce the bug /
   check out the PR and confirm it does what it claims. Two codebase checks first — REDUNDANCY (search
   by domain concept: already implemented → wontfix) and PRIOR-REJECTION (an out-of-scope KB). An
   unreproducible finding is REFUTED with attempts logged, or needs-human if it implies private state.
2. **Fix** — read build-change.md into the fix TASK (failing test first / red repro, smallest change,
   negative control).
   The finding TASK carries the same autonomy block as decompose-dag (goal · scope · non-goals ·
   stop · evidence · escalation · budget) and an intent packet on the manifest.
3. **Open PR against BASE** (integrator, never the builder; assert `baseRefName==BASE`) + reconcile
   any review bot (dispatch-lifecycle.md bot non-convergence).
4. **Build-blind REVIEW** (acceptance-review, + risk-review lens if the finding is a risk class);
   record reviewed_sha.
5. **merge_ready → the conductor** (merge-serialization.md): reviewed-SHA-fresh, ancestry-verified.
6. **Close with evidence:** the merge SHA + a completion note. A fix-backed close needs no extra human
   gate — the evidence chain is the authorization. A refutation/duplicate close is a one-way batch gate.
7. **Ledger flags** (ledger-contract.md): advance `BUILD_DONE → PR_OPEN → BOT → REVIEWED → MERGED →
   WT_CLEAN` only from file-verified state. If the fix is mergeable but acceptance needs load/prod
   data the fleet cannot reach: merge as `CODE_CLOSED`, open `VERIFY_AT_SCALE` OPS item — never
   claim full close.

## Rules

- Close ONLY off a verified merge, never off worker memory.
- One finding = one branch = one PR = one merge commit; same-file findings form a merge chain.
- Sizing: build-change's PR sizing seam applies — a sub-10-line finding folds into a neighboring
  finding's PR (both closes cite the shared merge SHA); one file never splits across two PRs.
- Lane B forks (gate-classification.md): draft both options, human gate — do not pick silently.
- The mission owns "how do I know the whole set is clean" (its convergence proof); this owns "how do I
  close one finding correctly".

## Completion

The finding is closed off a verified merge SHA with its negative control executed, refuted or
duplicate behind the batch gate, or parked (`CODE_CLOSED` + `VERIFY_AT_SCALE`, needs-human) with a reason.
