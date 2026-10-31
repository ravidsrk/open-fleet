# TODOS

This file is a pointer, not a backlog. Open work lives where it is machine-checked or
issue-tracked, so this surface cannot drift into "nothing open" while gaps stand:

- **Product roadmap (done 2026-10-25)** — [the October 20 roadmap](docs/roadmap.md) reconciles
  the release epic with the runtime expansion and new GitHub/paper research.
  It links the detailed work packages and distinguishes proposed experiments from
  existing release gates; dated reviews below remain historical evidence.
- **The 2026-09-28 release-readiness review** —
  [`docs/reviews/2026-09-28-release-readiness-review.md`](docs/reviews/2026-09-28-release-readiness-review.md):
  four P0 findings (the runtime scripts hardcode `orca` where Linux ships `orca-ide`; the published
  version is 1,372 commits behind with no GitHub Releases; five stale hand-typed pin and proof
  sentences; a schema line the 2026-09-28 re-pin missed), eight P1 findings, and a three-tier
  release path (0.7.0 → public beta → 1.0). Its findings are filed as #510–#525 under label
  [`release-readiness-2026-09-28`](https://github.com/ravidsrk/open-fleet/issues?q=label%3Arelease-readiness-2026-09-28)
  — that query, not this line, is the live open set. At the 2026-09-30 sweep
  [#511](https://github.com/ravidsrk/open-fleet/issues/511),
  [#515](https://github.com/ravidsrk/open-fleet/issues/515) and
  [#518](https://github.com/ravidsrk/open-fleet/issues/518) were still open; the ordered path past
  the 0.7.0 cut is the road-to-1.0 epic [#526](https://github.com/ravidsrk/open-fleet/issues/526).
- **The 2026-10-27 security audit** —
  [`docs/runs/2026-10-27-security-audit.md`](docs/runs/2026-10-27-security-audit.md) (#717):
  a tree-wide `harden-it` audit-only run over every first-party executable surface. It found 78
  findings, 3 of them P0, and closed HARDENED-WITH-OPEN-ITEMS. The wave files and verifier reports
  are under [`docs/runs/2026-10-27-security-audit/`](docs/runs/2026-10-27-security-audit/). Its
  follow-up fixes landed as #718 to #734, each naming the finding IDs it closes in its title, with
  a `changelog.d/secaudit-*.md` fragment. The report's findings table records each finding's state
  at run close, and the run-close sha256 inventory pins it, so nobody edits it afterwards. The live
  open set is the rows of that table whose ID no merged fix PR names. No issue label tracks the
  audit's findings.
- **Standing gaps** — [`docs/completion/GAPS.md`](docs/completion/GAPS.md): every finding
  between HEAD and the completion definition with a FINISH / CUT / DEFER decision (a dated
  snapshot; live proof counts are in the README's generated proof-status sentence). G-09
  (field proof) is the open DEFER row. Its tracking issue (#212) is closed; the register row
  stays open deliberately — a closed tracker is not a closed gap, and `docs/runs/README.md`'s
  field-proof plan is G-09's live tracker.
- **Field-proof plan** — [`docs/runs/README.md`](docs/runs/README.md#field-proof-plan-212):
  per-mission targets, tiers, terminals, and blockers for advancing `doctrine-only` missions.
  A tier moves only through a recorded mission run, never a relabel.
- **The 2026-09-11 deep review** —
  [`docs/reviews/2026-09-11-review.md`](docs/reviews/2026-09-11-review.md) (moved from the root
  `REVIEW.md` on 2026-10-14) and issues
  [#279–#307](https://github.com/ravidsrk/open-fleet/issues?q=label%3Adeep-review-2026-09-11) (plus
  #309–#318 from a second review of the same base). **Closed** — every finding landed in #308; #307
  closed when its release tags were published. Section or attack-id anchors are numbered per review,
  so a citation carrying one must name the dated file it means (#295).
- **The 2026-09-12 release audit** — issues and PRs #321–#338: `deny-hook.sh` word and redirect
  parsing, verifier evidence binding, `egress.py` receipt writes, `bundle.py` vendored protocols,
  `spawn_worker.sh` launch refusals, and the migration/governance mission contracts. Its evidence
  is under [`docs/reports/release-20260912/`](docs/reports/release-20260912/).
- **The 2026-09-10 deep review**, its predecessor, archived at
  [`docs/reviews/2026-09-10-review.md`](docs/reviews/2026-09-10-review.md) and issues
  [#255–#276](https://github.com/ravidsrk/open-fleet/issues?q=label%3Adeep-review-2026-09-10).
  Older code comments and fixtures citing "REVIEW.md §N" mean THAT document (#295).

Completed items are recorded in [`CHANGELOG.md`](CHANGELOG.md), not here.
