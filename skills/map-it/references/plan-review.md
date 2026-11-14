# Playbook — plan-review  (adversarial review of a plan, before anything is built)

Recipe: gstack `plan-ceo-review` scope challenge, `plan-design-review` / `plan-devex-review`,
`plan-eng-review`'s terminal-report exit gate, `autoplan`'s decision classification, and
`office-hours` alternatives generation. A plan is cheap to change and expensive to have been wrong
about. This reviews the PLAN — acceptance-review reviews the diff, risk-review reviews the
change surface.

## Lens order is the mechanism

Run the lenses in this order, each a FRESH worker that did not write the plan, each amending it
before the next one reads it:

1. **Scope (first).** Is this the right problem? Would a different framing collapse it? What is the
   actual outcome, or is the plan solving a proxy? What happens if nothing is done — real pain or
   hypothetical? Which sub-problems are ALREADY solved by existing code (map every one)? If the
   plan produces something people must obtain, how do they get it — or is that explicitly deferred?
2. **Design** — only if the plan changes a user-facing surface.
3. **DX** — only if the plan changes a developer-facing surface.
4. **Engineering, LAST, on the AMENDED plan.** Architecture, data flow, edge cases, failure modes,
   test strategy. Engineering first is the common inversion and it is wrong: it hardens a plan whose
   scope has not survived challenge yet, and the scope amendment then invalidates the engineering.

Each lens states, before it reads, what a strong plan on its axis would look like — the expectation
is written before the artifact, as in acceptance-review.

## Premise statements

The scope lens emits its premises as flat statements the human must agree with before the plan is
allowed to proceed: `PREMISE n: <statement> — agree / disagree`. Disagreement loops the scope lens,
it does not get overridden. Premises are how an unstated assumption becomes visible early instead of
becoming a rewrite later.

## Alternatives are mandatory

Non-trivial plans carry 2-3 distinct approaches — never one. At minimum: one **minimal viable**
(fewest files, smallest diff, ships soonest) and one **ideal** (best long-term trajectory); a third
may be laterally different. Each carries summary, effort, risk, pros, cons, and what it REUSES. The
review then makes a recommendation with a one-line reason tied to the stated goal. A plan with one
approach has not been reviewed; it has been elaborated.

## Decisions: classify, queue, and gate ONCE

Classify every decision the review reaches (gate-classification.md): mechanical decisions are taken
silently; taste decisions are taken with a recommendation and surfaced; and a **user challenge** —
the review concluding that the human's stated direction should change (merge, split, add, remove,
or reinterpret something they specified) — is NEVER auto-decided. User challenges QUEUE and surface
at ONE final gate, never as mid-run interrupts, and each carries five fields:

```
USER CHALLENGE
what the human said: …
what the review recommends: …
why: …
context we may be missing: …
if we are wrong, the cost is: …
```

The human's original direction is the DEFAULT; the review must make the case for change, not the
other way round. Scope EXPANSION is never a user challenge the review may auto-approve — the
denominator is frozen, and growth is scope creep routed back to the freeze.

**Urgency exception:** a security or feasibility finding that makes the plan unsafe or unbuildable
surfaces IMMEDIATELY rather than queueing. It is the only interrupt this playbook permits.

## Report shape (the exit gate)

The review report is the plan's TERMINAL section — the last heading in the file, written into the
plan itself, not a chat summary and not prose scattered in the body. It carries: the lenses that
ran and their status, the findings table, the alternatives with the recommendation, a **VERDICT**
line, and as its final line either `NO UNRESOLVED DECISIONS` or an explicit unresolved-decisions
block listing each queued item. A plan whose last heading is not the report has not passed this
gate — that check is mechanical and fails closed. A skipped lens is recorded as skipped with its
reason; the verdict is never a score averaged over the lenses that happened to run.

## Completion

Every applicable lens ran in order with engineering last on the amended plan; each lens wrote its
expectation before reading; premises are stated and agreed; 2-3 alternatives exist including one
minimal and one ideal, with a recommendation; every decision is classified, and every user
challenge is queued to one gate with all five fields; the report is the plan's terminal section
with a VERDICT and a final unresolved-decisions status. No code was written from this playbook.
