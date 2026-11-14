# Runtime policy — conductor-close (post-merge evidence closure, once per unit)

ACTOR: the COORDINATOR (conductor) itself, never a dispatched worker — the unit's
workers are released by the time it runs, and every record it writes is labelled
"coordinator". Methodology: none (mechanical record-keeping). Commits exactly ONE chore commit on BASE per close.

WHEN: after the unit PR is MERGED into BASE and its verdict review is posted. Not
before: every rule below binds evidence to the merged, reviewed tip, which does not
exist earlier. Field record: five wave-2 units closed (report: `docs/runs/2026-09-14-clean-sweep-tracker.md`).

INPUTS: the unit manifest; PR number; merge commit M; verdict review id; dispatch contract source + digest; coordinator-named nc-command; unit class.

CLOSE (in order; any mismatch is a STOP, logged, never patched over):
1) Resolve the tip: T := git rev-parse M^2 (the merged PR head). Assert T ==
   the verdict's reviewed_sha and git merge-base --is-ancestor T BASE. T !=
   reviewed_sha means the review is stale (see union-invalidates). M must be
   a merge commit: ledger-contract.md MERGED = merge-commit (not squash), so
   unit PRs merge only as merge commits (gh pr merge --merge, or merge_queue.py's
   merges endpoint, merge-serialization.md). A squash, rebase or
   fast-forward merge has no M^2: the merge is non-conforming, so STOP and
   raise a human gate naming M and its merge method. Fail closed: never
   derive T another way (not M, M^1, the PR's headRefOid or a guessed commit).
2) Re-run in a clean worktree at the merge tip: git worktree add --detach <scratch>/close-<unit> T;
   git status --porcelain empty; then the nc-command, the repo's static gate, and the full suite,
   each wrapped by the run's evidence recorder into a manifest OUTSIDE the worktree (the tree stays
   clean). All exit 0. Remove the scratch worktree after.
3) Append coordinator records: the three records go into commands[] labelled
   "coordinator <gate> at head", commit = T, wtree = git rev-parse T^{tree},
   with an artifact_note quoting the runner's summary line. Builder records
   at older trees STAY as true history; they are not edited or deleted.
4) Re-bind head/head_tree: head_sha := T and head_tree := git rev-parse T^{tree}, both RECOMPUTED
   from git, never copied from a note. Prepend a "CONDUCTOR CLOSE <iso-ts>" sentence to head_sha_role
   naming the old and new values and the T-vs-builder-head delta (git diff --stat, normally manifest +
   negctrl only). A re-bind without the prepend leaves stale prose describing a dead tree — the prepend
   is the step, not garnish.
5) pr fill: pr.number, pr.url, pr.reviewed_sha := T, pr.reviewed_wtree :=
   T^{tree}. Replace every "pending" SHA in commits[] with the real one from
   git log. If the worker wrote contract.source in brief form, correct it to
   the frozen spec file@dispatch-commit and check git show <ref>:<path> |
   shasum -a 256 == contract.digest; say so in a conductor_note.
6) verify.py: run the evidence-manifest.md verifier with --execute-nc at T.
   Record the per-leg outcome in the ledger row evidence. A RED leg is
   RECORDED, never hidden: the review leg RED (no independent APPROVED)
   parks the row needs-human with the ask and a run ref — the ledger
   contract allows no other class for it.
7) Commit: ONE chore commit on BASE with the manifest edits, the ledger row
   (MERGED/WT_CLEAN flips, park, evidence) and a loop-log line. Push with
   its egress receipt, then retire the unit worktree (dispatch-lifecycle.md guards).
   The loop-log line carries `egress.py head` for the run ledger, and the close
   first runs `egress.py verify --expect-ancestor <the previous close's recorded
   head>` plus one `--expect-ancestor <id>` per receipt written since: each id
   `egress.py write` printed, and each `egress_receipt` that `merge_queue.py receipts`
   lists — receipts appended since are expected; a rewritten or truncated ledger
   loses an anchored line, and only its id binds a receipt written after the last close.
   The anchors live in committed records the ledger writer alone cannot rewrite
   (#561). A run that sent nothing says so: `--allow-empty` in place of the id
   (no receipts otherwise exits 4). A mismatch (3) or exit 4 is a RED leg under rule 6.

Scope: the unit binds T (records must bind head_sha's tree — evidence-manifest.md); the integrated tree M is covered by the PR's merge-commit CI, never this close.

RULES:
- option-A (self-reference). A commit cannot name its own SHA, and a
  commands[] record cannot bind the tree of a commit that contains the
  record. So at BUILD the worker sets head_sha = its last CONTENT commit
  and names the pushed manifest-commit tip separately in worker_done. At
  CLOSE the conductor re-binds head_sha to the reviewed tip (step 4), the
  first point where the manifest commit is already history.
- union-invalidates. A merge of BASE into the unit branch changes the tree
  under every earlier binding. commands[] records, NC replays and verdicts
  made before the union are STALE until re-run at the post-union tip: the
  integrator re-runs the gates on the union, reviewers review the union tip
  (reviewed-sha-freshness.md), and step 2 re-runs at the merge tip
  regardless. Stale records stay in commands[] as history and never count
  as fresh.
- out-of-process-merge. A merge made outside the pipeline (a human merging
  while a review is in flight, another agent's PR landing on BASE) is
  disclosed, not normalised: record the actor, the merge commit and what
  was in flight, in the loop log and in the manifest; then re-verify from
  step 1 at that merge's tip. A merged unit cannot park on an open review
  finding: the review round posts as a record and a sticking finding goes
  to a fix-forward unit. A RED verify leg still parks the row per step 6.
- reattach. Review workers check out the reviewed SHA, which leaves the unit worktree on a detached
  HEAD; they leave it detached, commit nothing, and say so in worker_done. Whoever commits next in a
  review-touched worktree reattaches BEFORE the first commit: git status --porcelain empty; git checkout
  <unit-branch>; assert branch and HEAD == the expected tip. A dirty tree, a failed checkout or a tip
  mismatch is a STOP: never commit on a detached HEAD (the commit sits on no branch and the push leaves
  it behind).
- gates. A close that needs a human raises a gate instead of guessing:
  `gate-batch.py --run <run> add --title T --question Q` (owed; cite its
  `gate-batch.json` G<n> id in the park ref). Step 7 waits while `list
  --status owed --blocking <unit>` shows a gate; `stale` only reminds
  about old owed gates. `overtaken` means events answered first (record
  only, no ask); `waived` records the waiver reason as its answer.

## Completion

Merge commit M with M^2 == reviewed_sha; three exit-0 coordinator records at
T's tree appended; head re-bound with the CONDUCTOR CLOSE prepend; pr block
filled; no "pending" SHA left; verify.py run with per-leg outcomes recorded;
ONE chore commit on BASE pushed; unit worktree retired.
