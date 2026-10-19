---
name: modernize-it
description: >-
  Bring a dependency / framework / platform surface current, safely — CI green at every merge.
  Inventory outdated + advisories with reachability triage → order by a compatibility graph →
  upgrade one dep or coherent group per PR, adapting call sites (code-level
  expand/migrate/contract) to get off old majors while keeping CI green → re-inventory until every
  major is current or pinned-with-a-reason. Use when "update the dependencies", "upgrade
  everything", "framework migration", "get off the old major", "move from Postgres 12 to 16", or
  an unattended dependency-currency run. Not for stateful DB schema/data migration across deploys
  (hand that to migrate-it), ordinary feature delivery (ship-it), or advisory exploit proof (harden-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; the package manager + a
  green CI baseline. addyosmani deprecation-and-migration playbook — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one compatibility-graph node (a dependency or a framework major)
  state_machine: graph → order → upgrade → fix the breakage → review → land
  convergence: every node is current or pinned with a named reason, and CI is green at the tip
  ordering: topological on the compatibility graph — a node waits for everything it depends on
  parking: CURRENT-WITH-PINNED — a pin carries its reason and a human ref
  oracle: the repo's own suite green at the upgraded tip
---

# modernize-it — every major current or parked, CI green the whole way

You are the **COORDINATOR**. The unit is a COMPATIBILITY GRAPH node, not a finding: ordering,
ecosystem grouping, lockfile contention, code-level adaptation, and rollback constraints dominate —
PR-per-outdated-package is often actively WRONG. Composes `remediate-finding`, `acceptance-review`,
`risk-review` (data-migration lens as a REVIEW SIGNAL, not an execution engine), `runtime-prove`,
`research-brief` (INVENTORY reads the upstream changelog, not a summary of it), `resolve-conflict`
(lockfile and hot-file chains), `compound-learn`; rides `merge-serialization`, `reviewed-sha-freshness`, `dispatch-lifecycle`,
`liveness-resume`, `evidence-manifest`, `ledger-contract`, `attention-budget`,
`gate-classification` (a pin decision needs a human ref), `sandbox-policy` (a bumped package's
install hook is untrusted code — the run's single most dangerous execution surface). Worker TASK
pack: addy — never co-mount a second router.

Scope boundary: this mission owns DEPENDENCY/FRAMEWORK CURRENCY (bump → adapt call sites → CI green).
STATEFUL DB schema/data migration across deploys is a different unit, state machine, and proof — hand
a brief to `migrate-it`, which owns each deploy-gated phase. Its plan places the dependent upgrade
after expansion, preserves dual writes through backfill/switch, and contracts only after the
upgraded code is deployed, stable and no longer uses the old shape. Track the handoff until its
evidence returns; keep code-only upgrades here. Details: docs/missions/modernize-it.md.

## Two terminal outcomes

- **CURRENT** — every dep on a current supported version, zero reachable unaddressed advisories.
- **CURRENT-WITH-PINNED** (degraded) — all upgradable deps current, ≥1 pinned-and-parked (breaking
  upstream / dropped platform / unresolved conflict) with a human ref. Never reported as CURRENT.

## "Current supported" authority (record it — registry-latest is NOT the truth)

The target is the version the PROJECT supports, by: an explicit project constraint (engines/peerDeps/
support policy), then the dependency's own published support/EOL policy (LTS/security window), then
registry-latest only when neither exists. Record the chosen authority and its rationale in the unit
evidence manifest. A dep on a still-supported older major is CURRENT.

## Pipeline

```
INVENTORY (outdated + advisories; read the CHANGELOG not the version delta; reachability triage —
  dev-only/unreachable transitive is lower priority; never `audit fix --force`)
  → BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission modernize-it --base <BASE> --fork-point <sha
    recorded in the ledger header at BASE creation>; BASE ≠ default — dispatch-lifecycle.md)
  → order: security-critical-reachable → patch/minor (batch coherent groups) → majors (one per PR)
  → UPGRADE waves (one dep/coherent-group per PR: bump → adapt call sites, adding code-level
    deprecation shims / dual-run APIs where a major needs them → CI GREEN is the gate; lockfile
    regenerated not hand-edited; verify provenance on registry/maintainer change and install with
    lifecycle scripts disabled until provenance is verified — a bumped package's install hook is untrusted
    code (risk-review security lens). The lockfile is a hot mount-point file: upgrade PRs form a
    merge CHAIN (merge-serialization), regenerated at each rebase — and a rebase voids the review
    (reviewed-sha-freshness), so size coherent groups to keep the chain short)
  → FORCED-MIGRATION CHECK (risk-review data-migration lens): if an upgrade forces a stateful DB
    schema/data change, hand the migration and dependent upgrade to migrate-it as an `agent-brief`
    phase brief: expand → compatible upgrade/dual-write → backfill → switch → zero use → contract.
    Track the handoff in the inventory; migrate-it places the upgrade between expand and contract,
    with compatibility proven at each phase. Code-only upgrades continue through REVIEW below.
  → build-blind REVIEW (acceptance-review) → RUNTIME-PROVE (drive real entry points — green CI misses
    lazy imports and env-dependent init) → LAND
  → RE-INVENTORY → loop → outcome → REFLECT (`compound-learn`)
```

## Convergence proof

Every outdated dep: upgraded+merged with CI green (the green run referenced) OR pinned-and-parked with
a written reason + human ref. Every merge kept CI green (check the merge commits' checks — a red
pipeline never landed). Every upgrade that FORCED a stateful DB migration has a migrate-it handoff
tracking the dependent upgrade between expand and contract; unresolved handoffs remain parked in
the inventory with reason and human ref. Completed handoffs return phase/deploy evidence before
the node can count as current — never silently run inside this loop.
Advisory scan re-run clean (or each remaining one parked with reachability rationale). Final inventory
pasted. Manifest names CURRENT or CURRENT-WITH-PINNED.

## Ledger + supervision

Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (`-` if N/A;
SOURCE = inventory digest). Rows include Orca task id + dep/group fields (target · PR · CI · pin/
handoff). Stalls → WATCH; death → RESUME scoped to header coordinator + ledger task ids, git-verified.

## Anti-patterns

`audit fix --force` / mass-bump. Running a cross-deploy DB schema/data migration inside a currency loop
(hand it to migrate-it). Rename-in-place code migrations (breaks dual-running
deploys). Landing a red CI "to fix next PR". Bumping a major without its changelog. Dropping a compat
shim without a gate. Hand-merging a lockfile conflict. Letting a just-bumped package's install hook run
before its provenance is checked.

## Related
`migrate-it` (owns stateful schema/data change across deploys), `ship-it` (ordinary feature
delivery), `clean-sweep`, `harden-it`
(advisory exploit proof), `review-it` (data-migration lens as a per-diff review).
