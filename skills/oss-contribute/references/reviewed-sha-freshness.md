# Runtime policy — reviewed-SHA freshness

A build-blind review is only valid for the exact SHA it reviewed. The single most common way a
fleet ships unreviewed code is merging a branch whose head moved after review.

## The invariant

`worker_done.pr.reviewed_sha` MUST equal the branch head at merge time. If they differ, the review
is VOID and the PR must be re-reviewed for the new head before it can merge — with ONE equivalence
class: the manifest may also carry `pr.reviewed_wtree` (the tree SHA of the reviewed content,
`git rev-parse <reviewed>^{tree}` or `git write-tree` at review time). A head that moved but whose
tree is identical (a content-identical rebase or amend) does NOT void the review; any content
change does. The SHA check remains the GitHub-lookup key and the default — the tree check only
relaxes freshness, it never substitutes for proof the review happened (check_review in verify.py).

## What moves a head after review (voids it unless the tree is unchanged)

- A conductor/integrator **rebase** to resolve conflicts or union-merge onto BASE — changes the
  head SHA; if the resulting tree differs from `reviewed_wtree`, re-review; if identical, the
  review survives (the content the reviewer read is the content that merges).
- A **bot autofix** commit (Cursor BugBot Autofix and similar) landing after the reviewer's PASS —
  its tree differs by construction → re-review. See dispatch-lifecycle.md "bot non-convergence".
- Any late push by the builder — same tree test.

## Enforcement

- The reviewer records the SHA it reviewed AND the content tree (`reviewed_wtree`) in the evidence
  manifest.
- The merge step (merge-serialization.md) checks `gh pr view <n> --json headRefOid` against
  `reviewed_sha`; on mismatch it compares trees (`git rev-parse <head>^{tree}` vs
  `reviewed_wtree`) and only then bounces to re-review — requeue at the back.
- "Re-run gates green" is NOT a review. Only a fresh build-blind review of the new head restores
  freshness when the tree differs.
