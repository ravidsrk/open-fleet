# Playbook — completion-audit  (did the plan actually ship, item by item)

Recipe: gstack `ship` plan-completion. A wave that merged is not a plan that shipped. This playbook
re-derives, per plan item, whether the work exists — and, where the diff structurally cannot say,
converts the gap into a named verify command and an OPS item rather than a claim.

## 1. Extract the items

From the frozen spec / plan / issue set, extract every ACTIONABLE item: checkbox lines, numbered
implementation steps, imperative statements, file-level specifications, test requirements, schema
changes. IGNORE context and background sections, open questions (`TBD`, "decide later"), review
report sections, and anything explicitly deferred ("out of scope", "future", "P2+"). Cap the
extraction and say so if it bites. Each item carries its verbatim text and a category
(CODE · TEST · MIGRATION · CONFIG · DOCS). No extractable items is a recorded skip, not a pass.

## 2. Classify the verification MODE before judging

The diff cannot prove every kind of work; deciding *how* an item is verifiable comes first.

- **DIFF** — a change in this repo that would appear in `git diff <base>...HEAD`.
- **CROSS-REPO** — names a file or change in another repo. This diff cannot prove it.
- **EXTERNAL-STATE** — names state in a system outside the repo (a hosted config, DNS, a provider
  allowlist, an env var in a deploy target). This diff cannot prove it.
- **CONTENT-SHAPE** — a file must follow a convention. In-repo: DIFF. Elsewhere: one of the above.

Dispatch: DIFF → cross-reference against `git diff` and `git log` at the head. CROSS-REPO → if the
other tree is reachable, test for the path and cite it; unreachable → UNVERIFIABLE. EXTERNAL-STATE
→ UNVERIFIABLE by construction. CONTENT-SHAPE elsewhere → run the target's own validator if it has
one (pass ⇒ DONE, fail ⇒ NOT DONE) before falling back.

**Path-concreteness rule.** An item naming a concrete path MUST resolve to DONE or NOT DONE by
testing that path. UNVERIFIABLE is legal only when the target is genuinely abstract or the tree is
unreachable on this host. "I did not check" is not unreachable.

## 3. Verdict per item

- **DONE** — clear evidence, citing the file(s) in the diff or the verified path. A touched file is
  not evidence; the described behaviour must be present.
- **PARTIAL** — some of the item shipped; name what is missing.
- **NOT DONE** — verification RAN and produced negative evidence. Absence of a check is not NOT DONE.
- **CHANGED** — the goal is met by a different approach than planned; record the difference.
- **UNVERIFIABLE** — this run cannot prove or disprove it. Cite the exact check and where.

Honesty rule: code that *handles* a deliverable is not the deliverable. Between DONE and
UNVERIFIABLE, pick UNVERIFIABLE. Be conservative with DONE, generous with CHANGED.

## 4. Per-item disposition — never a blanket sweep

Every UNVERIFIABLE item is handled ON ITS OWN. A single confirmation covering "all the external
items" is the failure this playbook exists to prevent, and a human sentence ("Y — confirmed done")
is NOT verification: a sentence is not an artifact. Each UNVERIFIABLE item resolves to exactly one of

- **CODE_CLOSED + VERIFY_AT_SCALE** — the code side is merged and the acceptance evidence needs
  state the fleet cannot reach. Open an OPS item (ledger-contract.md) carrying a NAMED, runnable
  verify command or query and the owner who can run it. The unit is never flagged fully closed.
- **NOT DONE** — re-enters the gap list.
- **DROPPED** — an explicit, recorded scope decision through the gate (gate-classification.md).

NOT DONE items are the highest-priority output: they are the plan's gap list, reported as such.
PARTIAL items are reported with a note and do not silently become DONE.

## 5. Report

One line per item: verdict · category · mode · citation (path, SHA, command, or the named external
check). Then the tally by verdict. The tally is a description of the lines above it, never a score:
a run where half the items are UNVERIFIABLE reports that, and does not average it into a pass.

## Completion

Every extracted item has a mode, a verdict, and a citation; every concrete path was tested rather
than assumed; every UNVERIFIABLE item has its own disposition with a named verify command and an
OPS owner where it is `CODE_CLOSED`; no item was closed on a human's free-text assertion; the audit
ran in a session that did not produce the work. The audit is UNRUNNABLE-FAIL-CLOSED: if extraction
or classification cannot complete, that is a STOP with the reason, never a silent pass.
