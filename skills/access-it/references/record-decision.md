# Playbook — record-decision  (write the ADR, in the repo's own convention)

Recipe: Addy `documentation-and-adrs`, in the ADR format stated below. A decision the fleet made that a future
reader would be surprised by is not recorded by the commit that implements it. This playbook writes
that record — into the target repo's EXISTING scheme, never a second competing one.

## The triple test: is an ADR warranted at all?

All three must hold. Any one missing and there is nothing worth recording:

1. **Hard to reverse** — changing your mind later carries real cost.
2. **Surprising without context** — a future reader looks at the code and asks "why on earth?".
3. **A real trade-off** — genuine alternatives existed and one was chosen for stated reasons.

Easy to reverse: you will just reverse it. Unsurprising: nobody will wonder. No alternative: there
is nothing to record beyond "we did the obvious thing." Qualifying classes: architectural shape,
integration patterns between components, technology choices carrying lock-in, boundary and
ownership decisions (the explicit NOs matter as much as the yeses), deliberate deviations from the
obvious path, constraints invisible in the code, and a non-obvious REJECTION that will otherwise be
re-proposed in six months. A decision that fails the test still gets its DECISIONS line — the
ledger records every call; the ADR is only for the ones that need explaining.

## Match the repo's convention BEFORE writing

Read the target repo first and follow what is already there: the directory an ADR pointer names,
else an existing ADR directory, else the repo's documentation convention. Take its numbering
(scan for the highest existing number and increment by one), its filename shape
(`NNNN-slug.md` is the common one), its heading structure, its status vocabulary, and its markup
from the ADRs already in the tree. Only when the repo has NO convention do you choose one — and
then say, in the run report, that you chose it and what it is. Create the directory lazily: on the
first ADR, not speculatively.

## The record itself

The floor is small: a title naming the decision, and a few sentences giving the context, the
decision, and why. An ADR may be one paragraph — the value is recording THAT a decision was made
and WHY, not filling in sections. Add only what earns its place:

- **Status** (proposed / accepted / deprecated / superseded by <id>) — when decisions in this area
  get revisited.
- **Considered options** — when the rejected alternatives are worth remembering, with the reason
  each lost. Where a research brief or a plan review produced them, cite it.
- **Consequences** — when a non-obvious downstream effect needs calling out.

Where the decision came out of a gate (gate-classification.md), the ADR names the class and who
was accountable; where it came out of a freeze, it names the frozen spec.

## Never delete — supersede

A decision that no longer holds is NOT edited away and its file is NOT removed: history is the
point. Write a NEW ADR that states the new decision and what it supersedes, and mark the old one
superseded with a pointer forward. The same rule covers reversals discovered mid-run: the reversal
is its own record. A worker never rewrites an existing ADR's body except to add the superseded
marker and its pointer.

## Wire it to the ledger

The decision's DECISIONS line (ledger-contract.md) carries the ADR's path as its reference, so the
ledger stays the index and the ADR stays the prose. One decision, one ADR, one DECISIONS line; a
decision recorded in the ledger with no ADR when the triple test fired is an incomplete record, and
an ADR with no DECISIONS line is invisible to every later run.

## Completion

The triple test is recorded (which of the three held); the ADR continues the repo's existing
numbering and structure, or the newly chosen convention is stated; the file names the decision, the
context, and the reason; a superseding ADR links both ways and the superseded file is intact; the
DECISIONS line references the ADR path. No ADR was deleted or rewritten, and none was filed for a
decision that failed the triple test.
