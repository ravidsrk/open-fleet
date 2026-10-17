# Run archive

Recorded mission runs — the evidence behind each mission's `proof:` status. A run report
is what advances a mission past `doctrine-only`: `self-run` (run against this catalog) or
`external-run` (run against a repo that is not this catalog). Each report carries the fixed
point, the ledger, per-phase evidence, a run-close sha256 integrity inventory (inline, or
retained at a named location when the run's artifacts live outside this repo), and the
deviations that happened — recorded, not hidden.

`Binds?` is the only column that moves a mission's `metadata.proof`: **yes** means
`runtime/scripts/run_report.py` checks the report's bindings: the `RUN:` header's mission,
tier and commit, a recorded `verify.py … --manifest` invocation in the body and manifest ledger,
the ledger's command hash and resolvable content object, and the manifest and listed artifacts
inside this run's own directory re-hashing at that commit. These are worker-attested records;
the checker does not rerun the verifier or independently establish its verdict. Clean-environment
test reruns at the exact head and verification against the frozen contract and review authority
remain coordinator-owned. **no** means the recorded report does not satisfy these binding checks
here — history, kept, supporting no proof-tier advance.

Five reports in the archive read **yes** — the 2026-09-14 clean-sweep close, the 2026-09-16
prove-it run, and the 2026-09-21 harden-it run (the tiers earned under the binding gate), the
2026-10-13 ship-it mdtoc run, the catalog's first `external-run` tier advance, and the
2026-10-13 review-it Linux witness, filed at `doctrine-only` as #527 substrate evidence and
re-claimed at `external-run` on 2026-10-14 after it bound unchanged at that tier. Every other row reads **no**, and that
is the honest state, not a broken gate: three runs kept their artifacts outside this repository;
one recorded no inventory block; one never recorded its verifier transcript; one pinned an
inventory to a moved tree; three pin-it runs are bounded re-witnesses, not completed mission runs;
and two tracker rows are living ledgers — the 2026-09-14 one whose close binds in the next row, and the 2026-09-20 sign-386 one whose run is still open. The mechanism is
exercised by `tests/test_run_report.py`, which builds real
git repositories and includes a fully bound positive case alongside a dozen refused ones.

| Date       | Mission     | Target                        | Ran as       | Binds? | Outcome |
|------------|-------------|-------------------------------|--------------|--------|---------|
| 2026-07-13 | [clean-sweep](2026-07-13-clean-sweep-self-run.md) | this repo (doc-claims) | self-run | no — artifacts in the coordinator run dir | DRY (6 false claims fixed) |
| 2026-07-13 | [review-it](2026-07-13-review-it-external-run.md)  | garrytan/gstack PR #2252 | external-run | no — artifacts in the coordinator run dir | NO-GO (conditional, 0 Critical) |
| 2026-07-16 | [oss-contribute](2026-07-16-oss-contribute-external-run.md) | dodopayments/chimely (tracker) | external-run | no — artifacts in the fork worktree | CONTRIBUTED-WITH-PARKED (5 PRs, 4 assists) |
| 2026-07-17 | [clean-sweep](2026-07-17-clean-sweep-tracker-self-run.md) | this repo (tracker, 26 issues) | self-run | no — no inventory block | DRY-WITH-PARKED (22 closed, 4 parked) |
| 2026-08-28 | [ship-it](2026-08-28-ship-it-self-run.md) | this repo (proof-status slice) | self-run | no — 5/5 hashes re-derive at `748b328`, but the verifier transcript was never recorded | PROMOTION_READY (BUILT + promotion PR open) |
| 2026-09-09 | [clean-sweep](2026-09-09-clean-sweep-tracker.md) | this repo (tracker, 6 issues) | self-run | no — inventory pinned to a moved tree | DRY-WITH-PARKED (5 closed, 1 needs-human) |
| 2026-09-12 | [pin-it](2026-09-12-runtime-repin/) | this catalog's runtime doctrine against Orca 1.4.200 (#266) | self-run | no — the report states it is not a completed independent mission run | PARTIAL-WITNESS (doctrine repair prepared for review; `pins.json` stays at v1.4.199, all 21 missions stay `doctrine-only`) |
| 2026-09-13 | [pin-it](2026-09-13-pin-it-266/) | this catalog's runtime doctrine against the installed Orca 1.4.200 binary (#266) | self-run | no — see `proof_status --check`; the catalog claimed no tier above `doctrine-only` at the time | PINNED-WITH-PARKED (families needing a second datadir, an isolated v1.4.199 binary, a Windows/Linux host, a paid provider or owner-approved trust are parked with that precondition) |
| 2026-09-14 | [clean-sweep](2026-09-14-clean-sweep-tracker.md) | this repo (tracker, 6 issues; takeover) | self-run | no — the living ledger, not a binding report; the run's close binds in the next row | DRY-WITH-PARKED (10 units merged, #386/#235 + review legs parked) |
| 2026-09-14 | [clean-sweep](2026-09-14-clean-sweep-self-run.md) | this repo (tracker close; 10 units, 2 waves) | self-run | yes | DRY-WITH-PARKED (10 units merged, parks disclosed) |
| 2026-09-16 | [pin-it](2026-09-16-pin-it-416/) | this catalog's runtime doctrine against the installed Orca 1.4.203 binary (#416) | self-run | no — see `proof_status --check`; pin-it itself stays `doctrine-only` | PINNED-WITH-PARKED (sender-bound behavior replays need a live Orca terminal; OS/remote/paid-trust parks carry over; next re-pin #427) |
| 2026-09-16 | [prove-it](2026-09-16-prove-it-self-run.md) | this catalog (verify.py kind gate, PF-2) | self-run | yes | COVERED (PF-2; 4/4 mutants killed) |
| 2026-09-20 | [clean-sweep](2026-09-20-clean-sweep-tracker.md) | this repo (tracker, 10 issues) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | DRY-WITH-PARKED (4 issues closed with evidence after G1/G2 targeted repairs — verify 6/6 + 5/6-disclosed; 6 standing parks; promotion PR #486) |
| 2026-09-20 | [pin-it](2026-09-20-pin-it-427.md) | this catalog's runtime doctrine against the installed Orca 1.4.204 binary (#427) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | PINNED-WITH-PARKED (49 claims: 46 CURRENT, 1 PATCHED, 2 PARKED + carried register; #427 closed, successor #488; promotion PR #487) |
| 2026-09-20 | [sign-386](2026-09-20-sign-386.md) | this repo (#386: signed manifests + retention) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | CLOSED with evidence (U-SIG-1 648fcf77 + U-SIG-2 552f4af3, two full review rounds each; #386 closed; promotion PR #491) |
| 2026-09-21 | [harden-it](2026-09-21-harden-409.md) | this catalog's own verify.py / dispatch-sign.py / verify-gate.sh (#409) | self-run | no — the living ledger, not a binding report; the run's close binds in the next row | CLEAN (final re-audit: 0 unrefuted P0/P1; 6 rounds, 11 findings closed) |
| 2026-09-21 | [harden-it](2026-09-21-harden-it-self-run.md) | this catalog (#409 close: verify.py / dispatch-sign.py / verify-gate.sh; 10 waves) | self-run | yes | CLEAN (zero unrefuted P0/P1; 3 P0 + 1 CI-caught P0-class + 1 P1 + residual classes closed; gitleaks control held) |
| 2026-09-23 | [pin-it](2026-09-23-pin-it-488.md) | this catalog's runtime doctrine against the Orca v1.4.209 release binary (#488) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | PINNED-WITH-PARKED (3 behavioral + 2 text drifts fixed in the re-pin; parks carried; successor 2026-12-23) |
| 2026-09-28 | [pin-it](2026-09-28-pin-it-500.md) | this catalog's runtime doctrine against the Orca v1.4.215 release binary (#500, early re-pin) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | PINNED-WITH-PARKED (zero drift; additive surfaces noted; terminal-stop hedge confirmed; parks carried; successor 2026-12-28) |
| 2026-10-13 | [pin-it](2026-10-12-pin-it-224.md) | this catalog's runtime doctrine against Orca v1.4.224 (installed mac binary + Linux `orca-ide serve` substrate; delta vs the frozen 1.4.215 inventory + live replay) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | PINNED-WITH-PARKED (2 drifts patched; fencing / abandon retention / `terminal stop` / doctor-shape parks retired live; legacy replay + `caller.orcaSessionId` parked; successor 2026-12-28) |
| 2026-10-13 | [review-it](2026-10-13-review-it-linux.md) | stablyai/orca PR #28206 (external PR), executed on Ubuntu 24.04 via `orca-ide` 1.4.224 — the Linux witness (#527) | external-run | yes — filed at `doctrine-only` as #527 substrate evidence; tier claimed 2026-10-14 (header-only amendment, see the report) | NO-GO (0 Critical, 2 Required: submodule Force Delete toast hides superproject data loss; 4 read-only workers, target untouched, verdict retained not posted) |
| 2026-10-13 | [ship-it](2026-10-13-ship-it-mdtoc.md) | ravidsrk/mdtoc (new product repo) from a maintainer-frozen spec, on the Linux witness VM (#515) | external-run | yes | BUILT @ `046d1f8d` (6 slices, 110 tests; integrated FAIL → seam-fix slice → re-review PASS; offline local-merge lane, BASE pushed) |
| 2026-10-17 | [pin-it](2026-10-17-pin-it-229.md) | this catalog's runtime doctrine against Orca v1.4.229 (`a0cd1644`, source-delta re-witness vs v1.4.224 + carried live receipts; [delta inventory](2026-10-17-pin-it-229/delta-inventory-2026-10-17.md)) | self-run | no — the living ledger, not a binding report; binds, or does not, if a later promotion files one | PINNED-WITH-PARKED (1 stale Jira claim patched; 5 additive surfaces folded in: `orca jira`, `agent launch`, `reference`, `serve` containment, `task_not_startable.failureCount`, `automations runs` paging; parks carried) |

### Self-test campaign 2026-09-16

All 21 missions ran against orca-fleet itself on 2026-09-16; the [rollup](../reports/selftest-campaign-2026-09-16/rollup.md) is the curated index with the scoreboard and follow-up queue. Per-mission run dirs below (reports, transcripts, ledgers, manifests) — recorded history at each mission's current tier, not promotion bids:

- [absorb-it](campaign-2026-09-16-absorb-it/) — ABSORBED (queue dry at T0 and T1)
- [access-it](campaign-2026-09-16-access-it/) — PARKED, no UI target
- [attest-it](campaign-2026-09-16-attest-it/) — CONFORMANT-WITH-GAPS (34 VERIFIED, 8 GAP, NIST SP 800-218)
- [clean-sweep](campaign-2026-09-16-clean-sweep.md) — DRY-WITH-PARKED (0 closed, 9 parked; U434 needs-human secret)
- [deflake-it](campaign-2026-09-16-deflake-it/) — FIXED-LOCAL (F1 fixed; CI leg owed)
- [document-it](campaign-2026-09-16-document-it/) — DOCUMENTED (32/32 cells terminal)
- [field-test-it](campaign-2026-09-16-field-test-it/) — PARKED, no app/device target
- [floor-it](campaign-2026-09-16-floor-it/) — PARKED at FREEZE (human one-way gate)
- [harden-it](campaign-2026-09-16-harden-it/) — CLEAN (zero VERIFIED P0/P1)
- [map-it](campaign-2026-09-16-map-it/) — MAPPED-WITH-BLOCKED, no tier advance (the rollup's "#451 promotion" misnumbers PR #451, which is ship-it's fixture-target-app)
- [migrate-it](campaign-2026-09-16-migrate-it/) — PARKED, zero tables
- [modernize-it](campaign-2026-09-16-modernize-it/) — U1 BUILT and locally merged (ruff 0.16.5 to 0.16.7)
- [oncall-it](campaign-2026-09-16-oncall-it/) — PARKED, no production path
- [oss-contribute](campaign-2026-09-16-oss-contribute/) — PARKED, no qualifying upstream
- [pin-it](campaign-2026-09-16-pin-it/) — PINNED-WITH-PARKED (substrate-blocked probes)
- [prove-it](campaign-2026-09-16-prove-it/) — COVERED (PF-3 net)
- [reshape-it](campaign-2026-09-16-reshape-it/) — parked pre-BOOTSTRAP (confirm-surface gate open)
- [review-it](campaign-2026-09-16-review-it/) — GO on PR #445
- [root-cause](campaign-2026-09-16-root-cause/) — INCONCLUSIVE (H2 falsified; honest park)
- [ship-it](campaign-2026-09-16-ship-it/) — PARKED at entry (no input)
- [speed-it](campaign-2026-09-16-speed-it/) — OPTIMIZED-WITH-PARKED (H1 fixed; J1/J3 parked)

Proof status across the catalog is validator-enforced: a mission cannot claim a tier
above `doctrine-only` without a `proof_evidence:` path that resolves to a report here whose
inventory re-hashes at the commit its `RUN:` header names (`runtime/scripts/run_report.py`) —
`scripts/validate.py` also requires the filename to carry the mission name and the body to name
it. Start a new report from [TEMPLATE.md](TEMPLATE.md).

Every mutating self-run records the WIP-curve protocol from `attention-budget.md`: `waves=<n>`
in its `RUN:` header and one row per dispatch wave 1..n, each labeling `wave=<k>`, the WIP setting
(`builders=<n> reviewers=<n>`), builder throughput, verification latency (median and max), rework
rate and freshness violations with a measured value — `run_report.py` refuses a missing, partial,
doubled or out-of-range wave row ([TEMPLATE.md](TEMPLATE.md) shows the table). The 2026-08-28 ship-it self-run above records a first *qualitative* observation
(it reached verified-BUILT, not verified-CLOSED) — not a protocol-compliant point; the caps stay
ASSERTED until ≥3 runs at differing WIP settings measure verified-CLOSED-per-hour throughput.

## Field-proof plan (#212)

Every mission in the catalog except `clean-sweep`, `prove-it`, `harden-it`, `ship-it`, and `review-it` is `doctrine-only`; `clean-sweep`
earned `self-run` on the 2026-09-14 tracker run closed above, `prove-it` on the 2026-09-16 run,
`harden-it` on the 2026-09-21 run, `ship-it` the catalog's first `external-run` on the
2026-10-13 mdtoc run, and `review-it` `external-run` on the 2026-10-13 Linux witness archived above. Each advance is a **mission run** — Orca up, human
demonstrations under [`docs/reports/`](../reports/) say so themselves. Every mission has a row here,
and a test enforces that (#292): a mission with no path to a proof tier is a mission whose claim
cannot be checked, and adding one must not be cheaper than planning how to prove it. Targets that
make each run concrete, self-run candidates first:

| Mission | Target that exists today | Tier | Terminal to show | What blocks it |
|---|---|---|---|---|
| map-it | this catalog (report-only: planning branch, freeze commit, verified DAG) | self-run | `MAPPED` | Orca only |
| attest-it | this catalog against the agentskills.io spec at a digest — obligations = the spec's required fields, evidence = `scripts/validate.py` checks | self-run | `CONFORMANT` (or `-WITH-GAPS`) | Orca; a frozen catalog digest |
| harden-it | `runtime/scripts/verify.py`, `dispatch-sign.py`, `verify-gate.sh` — audit → PoC scenario → routed profile → fix → re-attack; the [gitleaks control](../reports/harden-it-externalrun/README.md) is one unit | self-run | `CLEAN` | — proven 2026-09-21/22 (#409, six rounds to a clean re-audit; see the archive rows above) |
| prove-it | `scripts/validate.py` + `runtime/scripts/verify.py` critical surface — proven 2026-09-16 (single-criterion wave PF-2 + WIP-curve row; the [PF-1 control](../reports/prove-it-selfrun/README.md) stays history) | self-run | `COVERED` | — (see the archive row above) |
| speed-it | the catalog-gates journey (`validate.py` + `tests/` + `proof_status`), declared budget e.g. ≤30s wall, guard in CI at the declared budget | self-run | `WITHIN-BUDGET` | Orca; a declared budget (human) |
| root-cause | the next real defect filed here, or an open bug in a small OSS repo | self-run or external-run | `DIAGNOSED` | a live bug + Orca |
| access-it | needs a web UI — an external repo with an axe-core baseline | external-run | `CONFORMANT` (or `-WITH-MANUAL-PARKED`) | a target + Orca |
| deflake-it | needs an observed flake — this suite ran flake-free in both audits; an external suite with a known flake | external-run | `STABLE` | a target + Orca |
| modernize-it | needs a lockfile — this catalog has no dependencies; an external repo with one | external-run | `CURRENT` | a target + Orca |
| pin-it | this catalog's `runtime/*.md` + `runtime/scripts/` against the installed Orca CLI — the audit's §2.1 claim inventory is the pre-cut backlog | self-run | `PINNED` (or `-WITH-PARKED`) | Orca (the re-witness oracle) |
| floor-it | this catalog: dimensions = test suite, validate.py, ruff, badge freshness — most are already wired, so the run is prove-fires + GUARD (injected violation must RED each gate; the check_constraints diff-watch is new) | self-run | `FLOORED` | Orca; the freeze gate (human) |
| reshape-it | this catalog's churn-hot modules (`git log --since=90d`) — likely `runtime/scripts/verify.py` / `scripts/validate.py`; characterization net pinned first | self-run | `RESHAPED` | Orca; the CONFIRM-SURFACE gate (human) |
| field-test-it | needs a device/emulator app — an external mobile repo | external-run | `FIELD-PROVEN` | a target + a paired device |
| clean-sweep | EARNED 2026-09-14: tracker run closed DRY-WITH-PARKED with artifacts in the run's own directory, an inventory pinned to the tip it names, and the verifier re-executed at promotion — [close report](2026-09-14-clean-sweep-self-run.md) | self-run | `DRY` (or `-WITH-PARKED`) | Orca |
| review-it | EARNED `external-run` 2026-10-13 (claimed 2026-10-14): stablyai/orca PR #28206 reviewed to NO-GO on the Linux witness with every artifact in the run's own directory — [run report](2026-10-13-review-it-linux.md) | external-run | `NO-GO` / `GO` | — (see the archive row above) |
| ship-it | EARNED `external-run` 2026-10-13: ravidsrk/mdtoc built from a maintainer-frozen spec to BUILT @ `046d1f8d` on the Linux witness via the executed-control lane — [run report](2026-10-13-ship-it-mdtoc.md) | external-run | `BUILT` | — (see the archive row above) |
| oss-contribute | the next upstream tracker — the 2026-07-16 chimely run kept its artifacts in the fork worktree | external-run | `CONTRIBUTED` (or `-WITH-PARKED`) | Orca; an upstream target + retained artifacts |
| absorb-it | this repo's own inbound PR queue once it has one; otherwise an external repo with open community PRs | external-run | `ABSORBED` (or `-WITH-PARKED`) | Orca; an inbound queue that exists |
| document-it | this catalog's own zero-coverage doc cells — `runtime/scripts/` has modules with no guide entry | self-run | `DOCUMENTED` | Orca; a frozen public surface to document against |
| migrate-it | needs a stateful schema — this catalog has no database; an external repo with a live migration | external-run | `MIGRATED` | a target with real data + Orca |
| oncall-it | a bounded external staging-service path set, with 2–4 frozen on-call questions per path; establish operability using the proof below | external-run | `OPERABLE` / `OPERABLE-WITH-PARKED` | Orca; staging failures that can be induced safely; an observable alert destination; human path/question and cost/ownership gates |
| offload-it | this catalog's own Run-on recipe — interview → snapshots → doctor → provision loop against a real provider | self-run | `OFFLOADED` (or `-WITH-PARKED`) | Orca; a funded provider account + agent login (human) |

For **oncall-it**, retain the question→signal queries and outputs, symptom alerts with two
severities and justified thresholds, linked runbooks, and test-fire receipts from the destination.
Record both oracle runs: a fresh source-blind worker locates an induced staging failure from
telemetry alone; a second fresh source-blind worker cannot locate it after instrumentation is
removed on a throwaway branch (RED). Neither worker wrote the instrumentation. Bind the evidence
to the recorded head SHA and removal control, then re-check every frozen question at the final
head. Missing staging, receipt or oracle evidence leaves the path parked; an incident resolved
using existing telemetry is insufficient. The [mission protocol](../../skills/oncall-it/SKILL.md)
owns the complete proof; a healthy service with missing telemetry is a valid starting target.

A run's report goes through the same gates as any change (PR, review bot, `validate.py`), and
`proof_status --check` keeps every tier honest until the report lands.
