---
name: reshape-it
description: >-
  Deepen a lived-in codebase's confirmed hot modules without changing behaviour: a churn-weighted
  shallowness inventory finds the modules whose interfaces are too wide for what they hide, a
  human confirms the target surface, a mutation-audited characterization net (prove-it's, consumed
  here) is pinned BEFORE any restructure, and each module is deepened one seam at a time with
  build-blind review. The unit is one module-deepening (one interface shrink at one seam). Use
  when "this module is a god file", "the interface is wider than the implementation", "too many
  imports to change anything", "architecture erosion", "refactor the hot path safely", "shallow
  modules", "deep modules". Not for dependency/framework upgrades (modernize-it), a findings
  backlog (clean-sweep), missing tests (prove-it — though reshape-it borrows its net), or perf
  (speed-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh. The target repo's test
  suite must be runnable and its mutation tooling available for the characterization net. A fix
  worker playbook pack (mattpocock, addyosmani, gstack) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one module-deepening (one interface shrink at one seam)
  state_machine: pin a characterization net → shrink the seam → prove behaviour unchanged → land
  convergence: every targeted seam is deepened with the net green before and after
  ordering: one seam at a time; the net is pinned before any shape change
  parking: RESHAPED-WITH-PARKED — a seam left alone names its risk
  oracle: the characterization net — behaviour preservation, not the new shape
---

# reshape-it — deep modules, same behaviour

You are the **COORDINATOR** of an architectural-erosion repair run. "The confirmed hot modules sit behind smaller,
testable interfaces, and behaviour is demonstrably unchanged" is a user-facing outcome with one failure mode that kills
most refactors: restructuring without a pinned behavioural oracle, so the diff is reviewed by vibes. This mission never
moves code before the characterization net exists and is mutation-audited. Composes `characterize` (the net protocol,
shared with prove-it), `decide-and-freeze` (CONFIRM-SURFACE bounds the target list with the human; headless publishes
the inventory and PARKS at the gate), `remediate-finding` (one deepening per unit — its reproduce-or-refute step
instantiates as the SCAN probes re-measuring the seam (the shallowness evidence IS the reproducible defect), and its
failing-first requirement instantiates as the CHARACTERIZE-pinned mutant RED before the deepening, per the §1 carve-out;
build-change's irreversibility gate applies to public-API breaks), `design-twice` (DEEPEN's interface fork, drafted not
argued), `record-decision` (a one-way API break is an ADR), `plan-review` (CONFIRM-SURFACE), `acceptance-review`
(build-blind review per unit); rides `evidence-manifest` (each unit carries the before/after interface-surface
measurement plus the legal negative control for a behaviour-preserving change — the speed-it carve-out: (a) the
CHARACTERIZE-pinned mutant still KILLED at `head_sha`, so the net is proven live on both sides of the move, and (b)
revert the deepening and the interface-surface measurement is no longer smaller; a plain revert-must-redden-the-suite NC
is a category error for a change whose entire contract is that the suite stays green), `merge-serialization`,
`reviewed-sha-freshness`, `dispatch-lifecycle`, `ledger-contract`, `sandbox-policy` (`PROFILE=rw` fix workers;
`PROFILE=ro` review workers), `gate-classification`, `attention-budget`. Worker TASK pack: one of matt | addy | gstack —
never co-mount.

DEFERRED READS, loaded on entering their phase and never at activation: liveness-resume.md on a
stall or resume · compound-learn.md at VERDICT (which modules resisted deepening and why).

## Terminal outcomes

- **RESHAPED** — every confirmed target module deepened: interface surface smaller by measurement,
  and the carve-out pair holds — the seam's pinned mutant still KILLED at `head_sha` (the oracle is
  live) AND reverting the deepening enlarges the interface measurement back.
- **RESHAPED-WITH-PARKED** (degraded) — ≥1 confirmed module cannot deepen without a one-way API-break or
  behaviour-change decision; it is PARKED with the exact decision named, never deepened silently.

## Pipeline

```
SCAN: churn-weighted shallowness inventory over a 90-day window, run PER CANDIDATE MODULE: CHURN =
  `git log --since=90d --format=%h -- <module-path> | wc -l` (commits touching the module — a
  path-count would pin every single-file module at 1) · WIDTH =
  exported-symbol count (e.g. Python: `grep -cE '^(def |class |async def |[A-Z_]+ =)' <module>`,
  plus `__all__` length; TS/JS: `grep -c '^export ' <module>`; adapt per language) · DEPTH =
  `wc -l` on the implementation file(s) behind the interface · FAN-IN =
  `git grep -lE '(from|import|require).*<module-name>' -- <dir> | wc -l`. Rank by
  CHURN × WIDTH ÷ max(DEPTH/100, 1), FAN-IN as tiebreak; the numbers order the inventory, they do
  not certify it. YAGNI cut: zero-churn modules drop out (a stable shallow module is not erosion).
→ CONFIRM-SURFACE (decide-and-freeze, one-way): the human bounds the target list from the
  inventory; what is not confirmed is not touched this run. Headless/spawned: publish the
  inventory and PARK at the gate — one-way doors are human-only, never auto-bounded
  (gate-classification; mission-scheduling already parks here).
→ BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission reshape-it --base <BASE> --fork-point <sha>;
  BASE ≠ default — dispatch-lifecycle.md). All deepening lands on BASE, never the default branch.
→ CHARACTERIZE (before ANY restructure): pin the existing behavioural net at each target's current
  seam, per `characterize` — the same protocol prove-it runs, held in one place. A module with no
  net does not enter DEEPEN.
→ DEEPEN (rw workers, remediate-finding): one module per unit — shrink the interface, push
  implementation detail down, keep every call site green. Public-API breaks hit the
  irreversibility gate (a plan + a human, never mid-wave). The unit's evidence pair: (1) the
  CHARACTERIZE-pinned mutant is still KILLED at the unit's head SHA (the oracle is live on both
  sides of the move); (2) reverting the deepening makes the interface-surface measurement no longer
  smaller — the reshape is revert-detectable even though the suite stays green by design.
→ build-blind REVIEW (acceptance-review: the diff is judged against the frozen surface intent;
  behaviour drift beyond the net is a finding) → LAND (merge-serialization).
→ RE-SCAN: re-run the same inventory probes over the confirmed surface; loop until every confirmed
  module is deepened (WIDTH measurably smaller) or explicitly parked — a median heuristic never
  closes the loop early — or the human stops the loop.
→ VERDICT: RESHAPED, or RESHAPED-WITH-PARKED with the decision register.
```

## Convergence proof (definition of done)

Every confirmed target module is accounted for: (a) a before/after interface-surface measurement
(exported symbols, parameter surface, import fan-in), (b) the legal negative control pair — the
pinned mutant still KILLED at `head_sha` and the revert-makes-it-shallow-again measurement — because
the suite staying green is the contract, not the proof, (c) build-blind review at the reviewed SHA
(the review, not the SHA-bound proof, applies the deletion test: the module's remaining interface
justifies its existence). The
confirmed surface never grew mid-run; newly discovered erosion joins the NEXT scan, not this one.
RESHAPED, or RESHAPED-WITH-PARKED with each parked module's one-way decision named.

## Ledger + supervision

Ledger header at T0 per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP`
— row schema per `ledger-contract.md`, WIP sized to `attention-budget.md`, one statement so the two
cannot drift (#383). WIP: builders=<n> reviewers=<n> (`-` if N/A; SOURCE = the shallowness-inventory digest + the confirmed surface). One row per (module, phase) — CHARACTERIZE and DEEPEN are separate units with separate SHAs; a god file with many seams is many DEEPEN rows:
id, surface before/after, net evidence, PR, reviewed SHA, verdict. CHARACTERIZE precedes DEEPEN
strictly per module; deepen waves run ≤3 builders. Stalls → `liveness-resume.md` WATCH; death →
RESUME (ledger-scoped, git-verified).

## Anti-patterns

Restructuring before the characterization net exists and is mutation-audited (the net is the only
thing that makes "behaviour unchanged" a claim with evidence). Growing the confirmed surface
mid-run ("while we're in here" — scope creep with extra steps). Deepening modules nobody changes
(YAGNI — erosion is churn-relative; a stable shallow module is fine). Landing an interface shrink
whose call sites broke "temporarily" (the net stays green or the unit does not land). Confusing
reshape-it with clean-sweep (an enumerable findings backlog) or prove-it (test gaps — the
characterization net borrows prove-it's harness, but its unit is a module, not a path). A parked
module silently deepened later in the same run.

## Related

`prove-it` (the characterization net's harness and mutation audit — its unit is a critical path,
not a module seam), `modernize-it` (dependency/framework versions), `clean-sweep` (a findings
backlog), `speed-it` (perf budgets), `map-it` (when the erosion's shape is itself undecided, map
first, reshape after).
