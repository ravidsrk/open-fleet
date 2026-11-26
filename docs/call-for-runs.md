# Call for runs

[Documentation](README.md) · [Submission guide](run-submission-guide.md) · [Run archive](runs/README.md)

Every mission listed below stands at `doctrine-only`: its doctrine is
written, and no run has yet been bound to evidence the checker can
re-derive (the missions that have earned a tier are absent from the list,
which a test holds equal to the doctrine-only set). Maintainer-run missions do not scale to the whole catalog, so
proof is open to anyone who can run a mission and submit the bundle. The tier your run earns
depends on its **target**, not on you: a run against this catalog earns `self-run`, a run
against any other repository earns `external-run` — the same tiers the maintainer's own runs
earn ([definitions](concepts.md#proof-status)); your name goes in the report's runner row. This
page lists every mission still waiting for its run; the
[run submission guide](run-submission-guide.md) turns your run into a
promotion PR.

How it works: pick a mission below, run it per its `SKILL.md` (targets that
exist today are in the [field-proof plan](runs/README.md#field-proof-plan-212)),
file the bundle as a PR following the submission guide, and CI's
`bind-check` job tells you whether it binds. When the bundle is green, a
maintainer reviews the run on its evidence and files the promotion: the
mission's `metadata.proof:` advances with your report cited as
`metadata.proof_evidence:`. The bar is the same for every runner —
`run_report.py` re-derives the bindings and the promotion gate re-checks
them before merge. Part of the roadmap epic's external-run flywheel; the
intake it rides was built for exactly this page.

What an accepted submission earns: runner credit in the run report, the
mission's worked-example envelope, and the CHANGELOG promotion line (the
submission guide's runner-credit convention fixes the exact shape), and the
mission's proof tier advancing on your evidence. No other payment, no
leaderboard.

## Open calls

Every mission below is at `doctrine-only` with no promotion in flight. The
list is machine-checked against the catalog: a test holds it equal to the
doctrine-only set, so it cannot silently rot — if you ran one of these and
it is still listed, the promotion has not landed yet.

<!-- call-for-runs:open:start -->

- [ ] `absorb-it` — needs an inbound PR queue: this repo's once it has one, else an external repo with open community PRs.
- [ ] `access-it` — needs a web UI: an external repo with an axe-core baseline.
- [ ] `attest-it` — this catalog against the agentskills.io spec at a digest.
- [ ] `deflake-it` — needs an observed flake: an external suite with a known one.
- [ ] `field-test-it` — needs a device/emulator app: an external mobile repo plus a paired device.
- [ ] `floor-it` — this catalog: prove each gate fires on an injected violation, then guard them.
- [ ] `map-it` — this catalog (report-only: freeze commit, verified DAG).
- [ ] `migrate-it` — needs a live schema: an external repo with a migration to run without downtime.
- [ ] `modernize-it` — needs a lockfile: an external repo with one (this catalog's runtime has no dependencies).
- [ ] `offload-it` — this catalog's own recipe: a funded provider account plus the agent login.
- [ ] `oncall-it` — this catalog's blind spots, or an external service missing alerts and runbooks.
- [ ] `oss-contribute` — the next upstream tracker, with artifacts retained in the run directory this time.
- [ ] `pin-it` — this catalog's runtime doctrine against the installed Orca CLI.
- [ ] `speed-it` — the catalog-gates journey against a declared wall-clock budget, guarded in CI.

<!-- call-for-runs:open:end -->

## Promotions already in flight

No promotion is currently in flight.

<!-- call-for-runs:in-flight:start -->

<!-- call-for-runs:in-flight:end -->

If every mission above has left `doctrine-only`, this page has done its job
and should say so in one line rather than list an empty set.
