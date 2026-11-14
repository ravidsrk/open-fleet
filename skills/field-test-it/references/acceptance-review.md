# Playbook — acceptance-review  (REVIEW: does it do the right thing, right?)

Recipe: Matt `code-review` two-axis (isolated); the review-army dispatch mechanics are fleet
runtime (dispatch-lifecycle.md), not a second loaded pack. Always-on for
any non-trivial diff. Build-blind: the reviewer is a FRESH session that did not write the code.

## Blind-fix first (anti-anchoring)

Build-blindness alone is not enough — a reviewer handed a diff anchors on it, and rationalizing
an artifact is cheaper than re-deriving the fix (order effects are empirically real). So BEFORE
opening the candidate diff, the reviewer reads only the finding/criteria and writes its OWN
expectation to its evidence notes: where the fix should live, its rough shape, and a confidence.
Then it opens the diff and reviews the delta against that expectation. Divergence is signal, not
error. Prefer a cross-vendor reviewer (different CLI/model than the builder) when the fleet has
one — mechanical independence beats instructed independence.

SOLO RUN — no second identity at all. This review cannot then be independent, and must not be faked:
`verify.py` requires an approval the fleet cannot self-issue, so a mutation unit cannot reach a
closed state. Record the verifier RED and stop the unit short of `REVIEWED`, or — ONLY for a unit that already
qualified `dark-eligible` at dispatch (Lane A, a cheap unfakeable oracle, off the irreversibility
stop-list: gate-classification.md) — re-dispatch it on the executed-control lane (`--lighting
dark-eligible --execute-nc`: the review is waived and the control becomes the only oracle). A
lit-required unit (auth, payments, secrets, migrations, deploys) stays RED. A reviewer that is the builder is not a reviewer. The 2026-08-28 ship-it self-run recorded
exactly that RED.

## The three axes (one coordinator-dispatched worker each, no cross-rerank)

- **Standards:** repo-documented standards (paste the files) + the Fowler 12-smell baseline, judged
  per hunk. Repo standard overrides the baseline; smells are judgement calls; skip what tooling
  enforces.
- **Spec:** does the diff faithfully implement the frozen spec / originating issue — missing/partial
  criteria, scope creep, implemented-but-wrong. Each finding quotes the spec line. Spec-source
  search order, first hit wins and is named in the report: the unit's frozen spec → the originating
  issue or finding → the acceptance criteria in the dispatched task → the PR description. No source
  found is a STOP, not a review against the reviewer's own idea of the requirement.
- **Test-adequacy:** for each claimed fix, would reverting the production change fail a test?

The COORDINATOR dispatches each axis as a fresh-context worker (a reviewer never fans out —
dispatch-lifecycle.md); aggregate side by side; do NOT rerank across axes (code can pass one and fail the other — that's the point).

## Anti-false-positive gate

A finding MUST quote its verbatim motivating code line; if it can't, confidence drops and it goes to
an appendix. Kills the "field doesn't exist on the model" FP class. Multiple axes flagging the same
`path:line` → confirmed, boost confidence.

## Output + the reviewed SHA

Findings side by side per axis with severity (Critical/Required/Nit/Optional/FYI), each with the
quoted line. The reviewer's summary brief stays under 400 words — the findings carry the detail;
a long narrative buries the Critical line and is where a reviewer starts arguing itself into
approval. Record the exact `reviewed_sha` in the evidence manifest (reviewed-sha-freshness.md) —
the merge depends on it.

## Round budget

Max THREE failed review rounds per unit. A unit still failing review after round 3 does not loop
again and does not merge — it PARKS with a gate (gate-classification.md) naming the sticking
finding. Nothing else in the fleet bounds the build→review→fix loop; without this cap a stubborn
finding ping-pongs an unattended run forever.

## Completion

Pinned fixed point (non-empty `git diff <fp>...HEAD`), ALL THREE axes reported with no cross-rerank,
every finding quotes its line, reviewed_sha recorded, blind-fix expectation written before the diff
was opened, round count ≤ 3. This axis checks conformance; refusal-under-attack is
risk-review's or harden-it's.
