# Playbook — explain-the-number  (MEASURE: a number is not evidence until it is explained)

Recipe: pstack `benchmark-checklist` and `principle-explain-the-number` (Lauren Tan, cursor/plugins,
MIT), after Brendan Gregg's checklist — restated as fleet rules; no worker loads pstack, so no pin. speed-it's metric contract
already fixes sample size, spread, and pinned conditions. This playbook is the rest. A number
the contract accepts can still be the wrong work.

## When

Before a baseline becomes a plan, before a before→after is a keep, and before a review treats
a pasted speedup as measured. A ballpark the human asked for is one run: still answer "did it
error?" and "did the work happen?", and say it is one run. A choice between options is never
a ballpark.

## The questions

Answer from a run. A guess from reading the code is not an answer.

1. **Limiter.** Why is the number not twice as good? Name the resource or code path that bounds
   it, from a profile or counters taken during a run you do not report (a profiler slows the
   work). If the load generator saturates first, you measured the generator. A change that did
   not move the number still needs the limiter, or you cannot call the change useless.
2. **Tuned.** Every side runs the way production runs it: release build, production flags, pools,
   caches as warm or cold as production, same versions and data. One side on defaults is a
   configuration comparison. A limiter that is a setting you are not changing means that side is
   untuned: tune it and measure again. When the declared experiment is that setting, the baseline
   keeps the production value and only that setting moves. If you cannot tune the rest, do not
   pick a winner.
3. **Limits.** Do the arithmetic. Bytes per second against disk and network. Operations per
   second times cost per operation against the cores. Time saved against the time the changed
   piece took. Removing a slice that is 10% of the run can make the run at most about 11%
   faster. A result past a limit measured a cache, a no-op, or a bug.
4. **Errors.** Count failures, non-success responses, and wrong outputs inside the timed region.
   Rejections are often fast. Timeouts and retries are slow. If the script does not count them,
   add the count before you trust the number.
5. **The work happened.** The request reached the server, the rows were written, the bytes were
   read, and the code used the result. A generator nobody iterates and a promise nobody awaits
   produce a number for work that never ran.

speed-it's contract still owns repeatability: median, spread, alternating sides, and a gap
inside the noise band is no difference. Do not restate it here.

## Completion — the verdict

- **faster / slower / no measurable difference** — the limiter is named, the sides are tuned or
  the untuned side is disqualified, the limits were checked, errors were counted, and the work
  was confirmed.
- **inconclusive** — a claimed difference with no limiter, an untuned side you still want to
  rank, or questions 4 or 5 unchecked. Name the gap. An inconclusive number is `unmeasured`.
  It is not a baseline, not a keep, and not a regression finding.

Record the verdict, the run count, the spread, and the limiter on the mission's attempt-ledger
line (speed-it defines it; the manifest carries the artifact path, evidence-manifest.md). One primary number in a PR body. The runs live in the artifact.
