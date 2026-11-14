# Playbook — mutation-hunt  (reviewer-side: prove the tests can fail)

Recipe: fleet-native — field-derived from the 2026-09-14 clean-sweep tracker run, no upstream pack.
The test-adequacy method behind acceptance-review.md's one-line axis ("would
reverting the production change fail a test?"). A suite that is green at the
tip proves nothing by itself — this playbook hunts the survivors that green
hides. Injected alongside `acceptance-review` at the review phase, never
alone. Field record: `docs/runs/2026-09-14-clean-sweep-tracker.md` (three
review rounds; every Required came from a forced repro, never from reading
green runs).

Authority: reviewers executing this playbook need PROFILE=rw, not ro —
killing mutants means running tests and writing scratch clones outside the
repo, which a read-only profile cannot do. This playbook grants nothing:
rw is the coordinator's sandbox-policy.md grant (the autonomous-write
opt-in in spawn_worker.sh), and a reviewer spawned ro must report the hunt
as not run rather than improvise write access. Under that grant the bounds
are: commit NOTHING, mutate only scratch copies, report findings — the
isolated worktree plus the PR gate is the same envelope that bounds builders.

## Killer mutants (the core move)

For each claimed fix, write your OWN killer mutant in a scratch clone —
production reverted or mutated — and re-run the covering test there. It must
go RED. A mutant the suite passes is a SURVIVOR: name what it proves unpinned
(the re-check position, the last-attempt write-through, the blocking join)
and file it at Required. Kill every mutant you write on the fixed code before
reporting; quote the RED output, not the conclusion.

## Forced schedules (concurrency)

Racy code gets forced schedules via barriers/events, never bare sleeps on
the correctness path: the interleaving under test must be UNAVOIDABLE, not
probable. Every probe rides the real lock/read/write path of the module
under test — a probe on a shadow path pins the shadow. Unforced trials
(0/60 with no forcing) measure the window's width, never its absence.

## Vacuity guard

A test whose probes can be bypassed by a behavior-neutral refactor must fail
LOUDLY: assert each probe FIRED with a literal expected count. A refactor
that quietly vacates the probes while the suite stays green is the same
class as a survivor — verify it REDs, or the "all mutants killed" claim is
false the next time production is innocently restructured.

## Residual demos

Windows the fix cannot close get a forced demo of the residual ITSELF plus
an honest outcome-set doc (drop vs corrupt vs poisoned ledger, with the
mechanism for each), never a vibes sentence. The demo transcript is
evidence; the doc is the claim it supports. A residual described but never
forced is a guess wearing documentation.

## Completion

Every claimed fix has a quoted killer RED in a scratch clone (removed
after); every forced schedule names its barriers; every probe asserts it
fired; every residual carries its demo transcript; survivors filed with
severity, green runs cited as context only.
