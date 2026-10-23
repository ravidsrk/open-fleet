# Playbook — decide-and-freeze  (the SPEC phase)

Recipe: Matt `grilling` + `to-spec` + `domain-modeling`. Turn intent into a FROZEN spec that is the
canonical fixed point for every downstream ticket, review, and acceptance test.

## Entry contract (two shapes, then one pipeline)

- **Input already frozen** (docs/spec handed in): VALIDATE it — load-bearing external deps are real
  and installable (research, don't assume), acceptance criteria are testable, boundaries explicit —
  then skip to the next phase. No grill.
- **Input is intent/draft**: run the grill below, then freeze.

## The grill (interactive; HITL leak if fanned to a worker)

**Before round 1**, write the current hypothesis of what the human wants and a confidence in it;
the grill is then aimed at what would falsify it, and the delta between that hypothesis and the
frozen spec is the round-1 record. Alongside it, publish a **Verified Current State** section —
what the code ACTUALLY does today, read from the tree, not recalled — so the grill sharpens
against facts. State the **premises** the scope rests on as flat statements the human agrees or
disagrees with (`PREMISE n: … — agree / disagree`) before scoping proceeds; a disagreed premise
loops, it is never overridden. Where the grill reaches an ADR-worthy decision, read
record-decision.md and write it.

On the coordinator terminal, run `grilling` + `domain-modeling` — **round by round**, not
question-by-question: ask the WHOLE frontier in one round, one bold-titled question + a
RECOMMENDED answer each (upstream format: ❓ question, ➡️ recommendation, phrased so a bare `"yes"`
accepts the recommendation without ambiguity) separated by a `---` rule
so no question buries the next, so a taste-class run can auto-pick per `gate-classification.md` and
a human answers in one pass. After each round, resolve
what the answers sharpened and ask the next frontier; facts that live in the codebase are
dispatched to a non-blocking fact-finder between rounds — never asked, never blocking the round.
**The join rule:** a question whose answer depends on an outstanding fact-finder stays OPEN until
that dispatch returns, and the freeze never happens with fact dispatches outstanding — independent
facts run concurrently, dependent decisions join on them.
- Sharpen overloaded terms against a `GLOSSARY.md` glossary (`CONTEXT.md` before matt v1.3.0 — matt
  skills read only the new name); account = Customer or User? An ADR only
  when hard-to-reverse ∧ surprising ∧ a real trade-off.
- Every DECISION goes to the human. Never answer the human's side.

## Seam-first spec

Before writing the spec, sketch the TEST SEAMS — prefer existing seams, the highest seam, the fewest
possible (ideal = 1), with one line per seam stating what it **catches** and what it **misses**.
The test surface is decided before the spec, not after.

## Freeze (human gate #1)

Publish the spec: objectives, acceptance criteria per capability, boundaries (explicit NOT-in-scope),
test strategy, seam list. **Redact fail-closed BEFORE the spec is filed anywhere**: every sink
re-scans the exact bytes it sends, and a high-confidence secret hit blocks every downstream sink —
a filing that cannot be scanned does not proceed. The human confirms with an EXPLICIT yes → FROZEN;
silence, "looks good", and an unanswered question are not a freeze. No re-open of frozen scope
without a backlog entry.

## Completion (checkable + exhaustive)

Every intent has an objective; every capability has ≥1 testable acceptance criterion; the seam list
is confirmed; boundaries name what is out; the human freeze is recorded. A spec with a capability
lacking a testable criterion is NOT frozen.
