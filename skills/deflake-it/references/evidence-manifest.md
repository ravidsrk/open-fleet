# Runtime policy — the evidence manifest (the definition of done)

How a fleet knows a unit is DONE — not trace-grading, which a coordinator cannot enforce (it holds no worker traces, and a trace proves an action attempted, not the
resulting state), but a two-part protocol: the worker emits a **SHA-bound evidence manifest**; an **independent verifier** checks its claims against **authoritative
state** (git, a clean-env test run, the runtime, the deploy target). A unit advances only when verification passes.

## 1. The manifest (every worker emits this in `worker_done`)

The worker writes it to the path the dispatcher passed as Orca's typed `--report-path` flag and names that path in `worker_done`. Shape (JSON; a mission may add fields):

```json
{
  "unit": "<task-id / finding-id / slice-id>",
  "base_sha": "<the SHA the work started from>",
  "head_sha": "<the SHA the work produced>",
  "base_branch": "<the integration BASE the PR targets>",
  "contract": {
    "source": "<authoritative ref the criteria derive from — frozen spec path@sha, the enumerated backlog, the advisory set>",
    "digest": "<sha256 of the unit's task spec as materialized at dispatch — the denominator is frozen per unit, not worker-chosen>",
    "criterion_ids": ["AC-1", "AC-2", "AC-3"]},
  "criteria": [{"id": "AC-1", "text": "<the exact acceptance criterion>", "addressed": true}],
  "commands": [{"label": "tests", "cmd": "pnpm test src/pay", "cmd_sha256": "<sha256 of that exact command line>", "exit": 0,
     "duration_s": 12.4, "commit": "<HEAD at run time>", "artifact": "docs/reports/<unit>/test.txt",
     "wtree": "<working-tree content fingerprint — must equal head_sha^{tree}>"}],
  "negative_control": {
    "did": "reverted the production line / applied mutant <id> via <tool>",
    "tool": "mutmut | cosmic-ray | stryker | pitest | cargo-mutants | go-mutesting | revert | hand",
    "mutant": "<pinned id, e.g. mutmut#7 validate.py:42 '>'->'>=' ; omit for revert/hand>",
    "result": "the criterion-bound test went RED (mutant KILLED)", "artifact": "docs/reports/<unit>/negctrl.txt",
    "command": "<the criterion-bound proof command, ONE string — split with shlex, never a shell line>",
    "paths": ["<production path(s) the revert control restores from base_sha>"]},
  "binding_audit": {"coverage": "AC-1..AC-3 (3/3)", "method": "criterion quoted, covering test quoted, criterion-violating mutation went RED"},
  "intent": {"goal": "<one sentence>", "ruled_out": "<what was not chosen>", "why": "<load-bearing rationale>"},
  "lighting": "lit",
  "lane": "A",
  "artifacts": [{"path": "docs/reports/<unit>/negctrl.txt", "sha256": "<sha256 of those exact bytes>"}],
  "pr": {"number": 0, "url": "", "reviewed_sha": "<SHA the reviewer approved>", "reviewed_wtree": "<tree SHA of the reviewed content — optional; a content-identical head move keeps freshness>"},
  "reviewer_mode": "<cross-vendor | same-vendor-fresh | instructed-isolation — how independent the review REALLY was>",
  "review": {"artifact": "docs/reports/<unit>/review.txt"},
  "toolchain": "<node 24 / python 3.12 / …>",
  "provenance": {"spec_version": "<governing spec/policy@version>", "model": "<impl model+version>", "reviewer": "<identity+timestamp>", "retention": "<log-receipt path>", "standard": "<EU-AI-Act-Art-12 | SOC2 | SSDF | none>"},
  "metric_contract": {"metric": "<streak / benchmark / coverage>", "target": "<pre-declared target + confidence>", "method": "<how measured, e.g. 30 runs varied seed>"},
  "parked": [{"item": "<what>", "reason": "<one-way / no-safe-sandbox / needs-human>", "gate": "<gate id>"}],
  "claim": "<the worker's own summary — informational only, NEVER the completion oracle>"
}
```

Field scoping by mission class: `base_branch`, `pr`, `review` and the revert/mutate form of `negative_control` are MUTATION-ONLY — report-only and planning units omit
them. A report-only unit's verdict binds to `head_sha` (the SHA it reviewed); its `negative_control` carries §3's class analogue (review-it: re-read every quoted line at
head_sha). Rules:
- `base_sha` and `head_sha` are REQUIRED on every class. Mutation units: pinned 40-hex real commits ("It works" with no SHA is not a manifest); other classes: a symbolic
  ref is NOTE-only.
- `contract` binds the manifest to THIS UNIT's authoritative denominator — the unit's task spec as materialized at decompose/enumeration time (a slice's criteria, a
  finding, an advisory), not worker-chosen. It is TWO-LEVEL:
  - **unit level** (this field): `contract.criterion_ids` is the COMPLETE id set of the unit's own task spec at `contract.digest`; `criteria` must carry an entry for
    every one — a worker cannot shrink its denominator; the verifier re-derives it (§2) and rejects a manifest that drops any id.
  - **mission level** (the coordinator's job, not the worker's): the UNION of all unit contracts must equal the mission's authoritative source (frozen spec criterion set
    / tracker enumeration / advisory scan). A criterion no unit's contract claims is UNASSIGNED WORK, surfaced at decompose verification and re-checked in the mission's
    convergence proof (e.g. ship-it's traceability table). This split is what makes a narrow slice completable: the slice proves ITS criteria; the mission proves nothing
    was left off any slice.
  For loop-based denominators (`clean-sweep source=tracker`) the two digests stay separate: the unit's `contract.digest` is always its OWN task spec; the ENUMERATION
  digest is mission state (ledger header's SOURCE field, re-derived each loop). The FINAL loop's enumeration is the mission denominator — a post-`T0` issue joins the next
  loop's set; verified units stay verified.
- `criteria` lists the ACTUAL acceptance criteria from the task spec, each marked addressed or not. A criterion with no addressing evidence is unmet work, not a waiver.
- **Evidence paths are repo-relative and PINNED.** Every path the manifest names (`negative_control.artifact`, `review.artifact`, `artifacts[]`) resolves inside the git
  toplevel — absolute, or escaping it, is refused — AND its bytes are fixed: the path is TRACKED at `head_sha` (the immutable form; the blob at that commit is what gets
  read), or its sha256 is listed in `artifacts[]` and matches. Untracked and unhashed is a claim ABOUT a file, not evidence.
- `negative_control` is REQUIRED for any unit that claims a fix or a test: show the proof FAILS when the change is reverted/mutated (a green test over reverted code
  proves nothing). Bind it to a NAMED mutation tool + a PINNED mutant id with a killed/survived verdict — a surviving criterion-violating mutant is a tautological suite
  and FAILS. Tools: `mutmut`/`cosmic-ray`/`stryker`/`pitest`/`cargo-mutants`/`go-mutesting` (per language), `hand` (compile-preserving hand-written mutant, diff quoted in
  the artifact), or `revert` (restore `paths` from `base_sha`). `command` + (for `revert`) `paths` make it RE-EXECUTABLE by §2's `--execute-nc` (NON-ZERO under the
  control in a throwaway worktree at `head_sha`, ZERO at clean `head_sha`); both are REQUIRED in the review-waiver lanes (`dark-eligible`, `--no-gh`), where the control
  is the only oracle and an artifact nobody ran is just text. Carve-outs: a perf fix compares before/after to the metric contract; a behaviour-preserving deepening
  (reshape-it) proves the seam's pinned mutant stays KILLED at head_sha AND reverting enlarges the interface measurement; a doctrine patch (pin-it) archives the pre-patch
  refutation receipt (the old claim's probe RED, tool `revert`), re-run post-merge.
- **Coordinator oracle scope:** test-only characterization and documentation units may put `oracle_scope` in the coordinator's digest-bound JSON contract (never the
  worker manifest): `{"kind":"characterization", "base_sha":"…", "head_sha":"…", "criterion_ids":["AC-1"], "paths":{"app.py":[2]}, "artifact_sha256":"<raw artifact
  sha256>"}`. `kind` is `characterization` or `documentation`; bind the exact commit pair, every criterion, explicit head-line numbers, and the exact hand-mutant artifact
  hash. The coordinator authorizes this concrete scope after inspecting the mutant. Characterization changes tests/prose only; documentation changes prose only. Tests,
  runner configuration, Makefiles and named executable proof inputs remain forbidden targets. Supported launch forms: interpreter scripts/Python modules, make, pytest,
  grep, and one plain `env [--]` wrapper. Unknown launch forms, inline programs and env assignments fail closed. Without this scope the production-change bind remains
  mandatory; every replay requires an assertion failure and clean-head success.
- `binding_audit` logs criterion↔test coverage for the same units: which `criteria[].id`s had their covering test quoted and mutation-checked against the criterion (§2
  samples it; a fix/test manifest without it fails).
- `commands` pastes real invocations + exit codes with artifact paths — never a summary. Produce them with `"$OPEN_FLEET_ROOT/runtime/scripts/evidence-run.py" --label L --manifest m.json --
  <cmd>`: a transparent wrapper (the child's exit code always passes through) that appends the record above, fingerprinting the tree with `wtree.sh` BEFORE the run. That
  fingerprint binds a run to content — §2 needs an exit-0 record whose `wtree` is `head_sha`'s tree; anything else is STALE.
- `pr.reviewed_sha` is the SHA the build-blind reviewer actually reviewed (see reviewed-sha-freshness.md). It gates the merge.
- `review.artifact` (the local reviewer record at head_sha) is REQUIRED on a mutation unit in the no-gh lane (dispatch `--no-gh`; merge-serialization.md) — the
  coordinator-attested stand-in for §2's GitHub review lookup; the gh lane and report-only/planning units omit it.
- `intent` is REQUIRED on mutation units: goal · ruled_out · why, all non-empty (else verification fails) — discarded agent reasoning captured, not the completion oracle.
- `lighting` is `lit` (default) or `dark-eligible` per gate-classification.md; what the verifier machine-checks is §2's "Lighting is legal" and review-WAIVER rows — the
  stop-list decision stays a human dispatch gate.
- `provenance` (optional, any class) is supporting metadata; a named standard (not `none`) makes `spec_version`, `model`, `reviewer` and `retention` required non-empty —
  presence only: not truth, operational logging, disclosure, marking or conformance. `retention` names the run's Rekor-style transparency-log RECEIPT (`log_index`,
  `entry_uuid`, `signature` over the signed inventory's digest) committed beside the inventory — an OPTIONAL coordinator upload with an egress.py receipt, never a gate;
  the check owed is OFFLINE — its fields binding that digest (verify.py today: presence only) — and proves the receipt covers these bytes, not that the log is reachable
  or trusted.
- `claim` is the worker's narration — the verifier ignores it except as a hint.

## 2. Independent verification (the coordinator, or a fresh verifier worker)

A DIFFERENT process/session — never a teammate (whose messages are in-band and self-certifying) — re-derives the manifest against authoritative state that lives OUTSIDE
it: the coordinator's frozen contract (scope), GitHub (review), git, and the EXECUTED negative control — deterministically, before any LLM judgment (impl: `verify.py`;
read build-change.md "The invocation" for its command line, lane flags included — a CHAINED-RUN manifest, evidence and commits in different clones, names both
`--git-dir` (the SHAs) and `--evidence-root` (#267's bound, escapes refused; split, evidence passes only on its `artifacts[]` pin, never the SHA clone's bytes)). Manifest
= claim; these are facts:

| Check | How (authoritative source) |
|-------|----------------------------|
| Unit scope is complete — no dropped criteria (do this FIRST) | re-derive the criterion id set from the COORDINATOR's authoritative `contract.source` @ `contract.digest` **as recorded in the dispatch record**, never the worker's manifest (a manifest cannot certify its own denominator; a manifest `contract.digest` that differs from the authoritative one is a denominator swap), and confirm `criteria[].id` covers it EXACTLY. Scope, pinned commit identities, signature/signed NC inputs and evidence validity are checked before any NC worktree, patch or command is run; rejection executes nothing. Rejected before any test is checked — passing tests on a shrunken denominator is a false "done" |
| Mission scope is complete — no unassigned criteria (coordinator, at decompose verify + convergence proof) | the union of all unit `contract.criterion_ids` equals the mission source's id set (frozen spec digest / final enumeration loop / advisory scan). A criterion claimed by no unit is unassigned work, not a waiver |
| The commit exists on the intended base *(mutation units)* | `git merge-base --is-ancestor <head_sha> origin/<base_branch>` after the merge; before merge, `git cat-file -e <head_sha>` and the PR's `baseRefName == base_branch` *(coordinator-run — not verify.py, which checks ancestry/existence only)* |
| Tests really ran on THIS content — the content-bound ledger *(verify.py `check_commands`)* | `commands[]` carries ≥1 record with `exit == 0` whose `wtree` equals `git rev-parse <head_sha>^{tree}` — written by `evidence-run.py`, which hashes the command and fingerprints the tree itself. FAIL-CLOSED: no record, or only records made on other content (STALE), fails the unit. The worker's own runner: it does not replace the clean-env re-run below, it makes "tests passed at that SHA" checkable instead of narrated |
| Tests pass at that exact SHA in a clean env *(coordinator-run — not verify.py)* | check out `head_sha` in a fresh worktree, run the suite, confirm green — do NOT trust the pasted output alone for the critical path |
| No credential reached the evidence *(verify.py `check_redaction`)* | the manifest JSON and every artifact it names are scanned for credential shapes (AWS keys, `ghp_`/`github_pat_`, private-key blocks, `password=`/`secret=` with a value, Slack tokens) — built-in patterns always, plus Gitleaks when installed; every consumer uses the same pinned bytes. Unreadable named evidence fails closed. A hit FAILS the unit: a SHA-pinned manifest is permanent, so rotate and re-emit |
| Each criterion binds to a test that exercises it — criterion↔test binding audit *(coordinator/human sample — not verify.py)* | on a sample of `criteria[].id`s (ALL of them when the unit has ≤3): quote the criterion, quote the test claimed to cover it, and confirm that test goes RED against an implementation that violates the criterion (mutate the behavior the criterion names via the manifest's named mutation tool — the pinned mutant must be KILLED; build-change.md's tautology guard covers authoring, this is its verifier-side twin). A green suite whose tests don't bind (tautological, wrong behavior, passes both ways) fails HERE, not at the clean-env re-run; coverage is logged in the manifest's `binding_audit` |
| The negative control really fails — EXECUTED, not read | mutation units: `--execute-nc`, exactly as **The executed negative control** below states. Report-only/planning units: the class analogue of §3 is re-checked (quoted lines exist at reviewed_sha / the frozen DAG re-verifies / the repro command re-runs red) |
| The review is fresh AND real *(mutation units)* | `pr.reviewed_sha == head_sha` (a rebase after review voids it — reviewed-sha-freshness.md — unless `reviewed_wtree` matches the head's tree, i.e. the move was content-identical) AND an APPROVED review at `head_sha` by a non-author OWNER/MEMBER/COLLABORATOR (`gh api repos/<repo>/pulls/<n>/reviews`) — a worker-set `reviewed_sha` is not evidence a review occurred — AND **no** independent reviewer's latest review within this content's history is `CHANGES_REQUESTED`: derive equivalent trees from all authoritative review commits, regardless of the worker's selected SHA, and fail closed on unresolved objects. A later unrelated review cannot withdraw a relevant objection; COMMENTED/DISMISSED on equivalent content can. A second approval cannot override it (#317) |
| The review-WAIVER lanes are closed to text | `dark-eligible` (gate-classification.md) and the no-gh lane (dispatch `--no-gh`, whose review is the manifest's `review.artifact`, a local record at head_sha) both remove the GitHub authority, leaving the negative control as the ONLY oracle. Both therefore pass ONLY with an EXECUTED control (`--execute-nc`) on top of the out-of-band coordinator contract; without it the unit is RED with a message naming the lane |
| The change is real on base *(mutation units)* | after merge, a file/symbol from the unit is greppable on `origin/<base_branch>` |
| Deployed == reviewed (ship only) *(coordinator-verified)* | the deployed revision equals the reviewed/merged SHA |
| The metric contract is met (measurement units) | the benchmark/coverage/streak satisfies the manifest's `metric_contract` (pre-declared target + confidence + method), not a lucky single run |
| The review was independent | `reviewer_mode` is recorded AND machine-checked for a legal value (verify.py); whether reviewer/verifier artifacts are byte-identical to (or trivially derived from) the worker's own output is a COORDINATOR judgment; instructed isolation is named as the weaker guarantee it is |
| Intent packet is present *(mutation units)* | `intent.goal`, `intent.ruled_out`, and `intent.why` are non-empty strings — presence only; wisdom is a human/taste check |
| Lighting is legal | `lighting` is `lit` or `dark-eligible` AND matches the dispatch-supplied value — a swap fails (verify.py); with dispatch-supplied `--lane`, a lane swap, a Lane-0 mutation, and dark outside Lane A also fail — the stop-list eligibility itself stays a human gate at dispatch (gate-classification.md) |

**The executed negative control** (§2, mutation units, `--execute-nc`): `verify.py` checks out `head_sha` in a throwaway worktree, APPLIES the control (`revert`: `git
checkout <base_sha> -- <negative_control.paths>`, falling back to `git revert --no-commit base..head` only when no paths are given and the range is linear; `hand`: `git
apply` the diff quoted in the artifact), seals it as a throwaway commit, and requires `negative_control.command` to exit 0 clean, NON-ZERO under it, 0 clean again (each
in a fresh worktree/HOME/TMPDIR, so no phase can tell which one it is in). That command is NOT the unit's to choose: the coordinator supplies it out of band as
`--nc-command` and the manifest must agree, with no fallback (#279) — the `commands[]` ledger is worker-run (`evidence-run.py`), so manifest and ledger are one authority
twice, and a worker nominating its own command picks one failing under the control and passing clean (`grep -q FIXED calc.py`) without ever running the proof. The control
must BIND TO THE CHANGE (#280): the paths it restores — and every endpoint in a `hand` diff — must be production paths `base_sha..head_sha` really changes (except the
coordinator oracle scope above), with every edited coordinate bound to the Git-applied diff before running the proof (offset relocation is refused); context cannot
authorize a mutant, nor can a decoy or TEST/runner-config path (reverting the test kills the oracle, not the behaviour); the range fallback is refused at admission when
the unit touches test/oracle inputs; and the RED must carry an assertion failure, not an ImportError (a STILLBORN MUTANT) or silence. A command that passes under the
control is TAUTOLOGICAL and fails; so does a control that changes nothing, a tool with no replay, a missing command, or any git error. The static artifact is read for
corroboration (a "survived / not killed" artifact fails) but is NEVER sufficient alone — it is worker-written text.

Verification failing on any required check → NOT done; re-dispatch, or SUSPECT if provenance says done but git disagrees.

At run close the coordinator writes an **integrity inventory** beside the final report — sha256 + producer + timestamp for every artifact the run's manifests reference
(§1's `artifacts[]` are its per-unit half) — and SIGNS its entry set (`inventory.py sign`, required by run_report.py once `.orca/dispatch-pubkey` is committed). RESUME
and any later audit reject a changed hash.

## 3. Standing definition-of-done floor (every mission, on top of its own contract)

A unit is done only when its own acceptance criteria AND this floor hold. It is scoped by MISSION CLASS — a negative control is always required; what one IS differs:

- **Mutation units** (ship-it, clean-sweep, oss-contribute, harden-it, speed-it, modernize-it, prove-it, deflake-it, access-it, pin-it, floor-it, reshape-it,
  field-test-it, migrate-it, oncall-it, absorb-it, document-it, offload-it): runtime-verified, not just compiled/typechecked; no new red at head SHA; the negative control is the §1
  proof, EXECUTED per §2. Sampling audits (revert-audit, pinned-mutant re-run, probe re-witness) run on **≥10% of the unit set, rounded UP** — this is the authoritative
  floor the missions cite, and a mission claiming a sample it did not take fails the unit (#358).
- **Report-only units** (review-it, attest-it): no code is touched (that IS a checked invariant — a dirty worktree fails the unit); the negative-control analogue is
  SOURCE-BINDING: every finding quotes a line that exists at `head_sha` and the verdict binds to that SHA — a quoted line absent there is fabricated and fails the unit.
  For attest-it that analogue is INDEPENDENT RE-DERIVATION: each obligation's evidence re-derives from authoritative state (code, config, live system), never narration.
- **Planning units** (map-it, root-cause diagnosis): the negative-control analogue is ARTIFACT VERIFICATION: the frozen DAG passes decompose-dag's verify section / the
  reproduction command was actually run and its failing output is pasted; a decision ticket answered by the agent instead of the human fails the unit.
- **Every class**: evidence exists (the manifest is present and SHA-bound) and anything not done is PARKED, named with a reason and a gate, never silently dropped.
