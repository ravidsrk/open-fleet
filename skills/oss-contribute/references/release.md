# Playbook — release  (the release state machine; version → promote → deploy)

Recipe: gstack `ship` (version state machine, verification gate, bisectable commits) + `land-and-deploy`
(staged rollout, revert-at-every-failure). A gstack `/ship` worker runs with `gstack-config set
ship_greptile_early false`: its early draft PR would publish the branch ahead of this machine's
review and gates. Release is a STATE MACHINE, not one phase. Named states:

`BUILT → PROMOTION_READY → RELEASED → DEPLOYED_AND_VERIFIED`

Which state is reachable depends on authorization and deploy availability — a mission stops at the
highest state it is authorized and able to reach and names it.

## BUILT (entered by landing)

Landing is merge-serialization.md doing its job: every unit of the wave `merge_ready`
(reviewed-SHA fresh), the conductor draining the queue in arrival order, hot-file chains
serialized, each merge ancestry-verified (`git merge-base --is-ancestor <mergeCommit>
origin/<BASE>` AND state=MERGED AND baseRefName==BASE AND a symbol from the unit greppable on
BASE), the merge SHA ledgered, worktrees torn down only at `WT_CLEAN` (never an active/unmerged/
dirty one). BUILT means on the integration BASE, verified — it does NOT mean shipped; the
BASE→default promotion is the separate one-way human gate below. BUILT is a wave state over the
whole train, never a unit gate — the per-unit ledger flag is `BUILD_DONE` (ledger-contract.md).

## PROMOTION_READY

Version bump: a deterministic classifier reads state (FRESH / ALREADY_BUMPED / DRIFT_STALE_PKG /
**DRIFT_UNEXPECTED → STOP**); the bump LEVEL stays agent judgment; workspace-queue-aware slot pick avoids
version collisions. Changelog + bisectable dependency-ordered commits. **Fresh-evidence verification
gate:** if ANY code changed since the last test run, re-run — "should work now → RUN IT".
**Doc-sync unit (before the promotion PR):** a named subagent pass syncs the docs to what the wave
actually shipped, running doc-coverage over the wave's diff (read doc-coverage.md here) — README
claims, guides, and diagrams re-read against the merged tree; drift is fixed as its own unit (never
clobber CHANGELOG history, never bump VERSION silently). Skipping it lets drift accumulate into the
next clean-sweep.
**Error-budget gate:** where the target declares an SLO, read the budget REMAINING before claiming
this state — >20% ships normally; 0-20% is slow-rollout-only, no high-risk change; exhausted freezes
feature promotion until reliability work recovers it. No SLO means no gate, recorded as absent, never
assumed green. **Operability gate** (read instrument.md — its ALERT, RUNBOOK and TEST-FIRE steps are
this gate's protocol): at least ONE symptom-based alert exists for this surface, its runbook is
written and linked, and the alert has been TEST-FIRED with the receipt in the ledger — an alert
nobody has ever seen fire is not an alert. Open the
BASE→default promotion PR with the traceability table and an `accountable: <human>` line naming
who owns the Verdict (gate-classification.md one-way). STOP here unless that human authorizes
promotion.

## RELEASED (human-gated, one-way)

The human merges the promotion PR. Verify state=MERGED on default + greppable. Merge ≠ deploy.

## DEPLOYED_AND_VERIFIED (OPS/authorized)

FIRST read observe.md and capture its baseline (its step 1 runs BEFORE the deploy — change-vs-baseline is
impossible afterwards). Record the **deploy-config digest** (the deploy target's effective
configuration, hashed) in the ledger next to the released SHA: a digest that differs from the last
deployed one means the target moved underneath the release, so the dry run RE-RUNS and its result
is a human gate before the deploy proceeds. Advance / hold / roll back at each rollout stage is
decided against observe.md's change-vs-baseline thresholds, not against absolute numbers, and a
high error-budget burn during the window is a HOLD signal read the same way as an elevated error
rate. Then: deploy-strategy auto-detect (fly/render/vercel/netlify/heroku/railway +
Actions); staging-first option (same health checks on staging before prod); a REVERT option offered at
EVERY failure point (deploy fail, canary fail: `git revert -m 1 <merge-sha>` or a revert-PR if
branch-protected). The DEPLOYED revision must equal the RELEASED SHA (evidence-manifest.md). Then hand
to observe's canary loop; this state is claimed only after the window is green.

## Completion

The manifest names the terminal state reached with its evidence (merge SHA / deploy revision) and,
if stopped early, the authorization it is blocked on. Never claim a higher state than reached.
