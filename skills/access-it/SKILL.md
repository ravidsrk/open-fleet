---
name: access-it
description: >-
  Drive a FROZEN page/flow/component set to WCAG 2.2 AA conformance (the engineering target that
  satisfies EAA / ADA / Section 508, which formally reference WCAG 2.1/2.0): a
  deterministic axe-core oracle clean on the surface plus a mandatory negative control (revert the
  fix, the violation returns), with the hard ~30-40% automation ceiling forcing screen-reader and
  cognitive criteria into a first-class human-AT park. The unit is one success-criterion violation
  instance on the frozen surface. Use when "accessibility", "a11y", "WCAG conformance", "screen
  reader", "keyboard-only operability", "ARIA", "axe-core", "Section 508 accessibility", "color
  contrast". Not for building a keyboard feature or shortcut (ship-it), a security exploit loop
  (harden-it), a PR merge verdict or a per-diff accessibility lens (review-it), a discovered
  backlog (clean-sweep), or standards attestation (attest-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; a deterministic a11y oracle
  (axe-core / Lighthouse) and a runnable surface. A fix worker playbook (addyosmani, mattpocock, gstack)
  — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one success-criterion violation instance on the frozen surface
  state_machine: axe scan → fix → re-scan → revert control (the violation returns)
  convergence: the axe oracle is clean over the re-enumerated frozen surface
  ordering: structural items serial (one landmark fix moves later instances); the rest parallel
  parking: CONFORMANT-WITH-MANUAL-PARKED — the automation ceiling is owed to a human AT reviewer as a standing terminal
  oracle: a deterministic rule engine (axe-core) over a frozen surface, incomplete by construction
---

# access-it — WCAG 2.2 conformance over a frozen surface

You are the **COORDINATOR** of an accessibility conformance run. "Make this surface WCAG 2.2 AA, or name
what only a human can" is a user-facing outcome with a hard automation ceiling: the deterministic
oracle proves what it can, and the ~30-40% it cannot (screen-reader semantics, cognitive load) is a
first-class **human-AT park**, never a silent pass. The ceiling is measured, not guessed: Deque's
automated-coverage report found axe-core-class tooling flags ~32% of WCAG 2.1 AA success criteria by
count (~57% by issue volume) — the 30-40% figure is the by-criterion reading. Composes `decide-and-freeze` (FREEZE is the
one-way gate), `decompose-dag` (enumerate violations
into a DAG over the frozen surface), `remediate-finding` (fix each), `browser-drive` (DETECT and RE-VERIFY drive the surface through it), `acceptance-review` (build-blind
review of each fix), `compound-learn` (retro); rides `evidence-manifest` (each fix carries the axe
result + a revert-to-violation negative control), `sandbox-policy` (`PROFILE=rw`),
`merge-serialization`, `reviewed-sha-freshness`, `dispatch-lifecycle`, `liveness-resume`,
`ledger-contract`, `attention-budget`. Worker TASK pack: one of matt | addy | gstack — never co-mount.

DEFERRED READS, never at activation: human-handoff.md at PARK, and whenever a Design Mode capture is requested.

## Terminal outcomes

- **CONFORMANT** — *near-unreachable*: only when the frozen surface has NO success criteria past the
  ~30-40% automation ceiling (rare — most surfaces have screen-reader/cognitive criteria). The oracle
  is clean across the surface, every criterion is covered, and each fix's negative control holds.
- **CONFORMANT-WITH-MANUAL-PARKED** (degraded) — the automatable criteria are clean, and the criteria past the
  automation ceiling (screen-reader / keyboard-trap / cognitive) are PARKED to a human + assistive-tech
  reviewer, each named with the criterion and why the oracle cannot decide it.

## Pipeline

```
FREEZE (decide-and-freeze, ONE-WAY) the surface: the page/flow/component set × the WCAG 2.2 AA criteria — the
  denominator, digest-locked. The human confirms it; headless/spawned publishes the proposal and PARKS there.
  → BOOTSTRAP integration BASE ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mission access-it --base <BASE> --fork-point <sha
    recorded in the ledger header at BASE creation>; BASE ≠ default — dispatch-lifecycle.md)
  → DETECT: run the deterministic oracle against the surface rendered at the BASE head (`oracle=`,
    frozen at T0: default `axe` — an automated rule engine; alternative `design-rules`, a catalog of
    the target's own component/contrast/target-size rules run as a deterministic pre-pass whose
    output feeds the same DAG); enumerate violations into a DAG.
  → FIX (rw workers, remediate-finding): each violation fixed at its instance; structural items
    (landmarks, heading order) serialized as they are global.
  → build-blind REVIEW (acceptance-review: semantics, not just the oracle — an aria-label stuffed to
    silence axe is a finding) → LAND (merge-serialization)
  → RE-VERIFY at the BASE head: the oracle goes clean on the frozen surface AND the mandatory negative
    control holds — revert the fix and the violation returns (evidence-manifest). A fix with no
    revert-to-red is not proven.
  → PARK: criteria past the automation ceiling routed to a human + assistive-tech reviewer, named.
  → VERDICT: CONFORMANT, or CONFORMANT-WITH-MANUAL-PARKED with the human-AT park register.
```

## Design Mode captures are requestable evidence

A violation instance whose rendered context matters (contrast, target size, focus order) may cite
a Design Mode capture as evidence: the human clicks the element in Orca's browser and it lands in
chat with its DOM, computed styles, cropped screenshot, and source file/line (when a dev-mode
source map is available). A capture is requested through human-handoff.md, arrives as DATA, and
never substitutes for the oracle's re-scan or the revert control.

## Convergence proof (definition of done)

Every success criterion in the frozen (surface × WCAG 2.2 AA) denominator is accounted for: the
deterministic oracle is clean across the surface, each automatable criterion is covered with a fix whose
negative control (revert → violation returns) holds, and each criterion past the automation ceiling is
PARKED to a named human-AT reviewer with the reason the oracle cannot decide it. The verdict is
CONFORMANT or CONFORMANT-WITH-MANUAL-PARKED; the denominator was never shrunk to only the automatable
criteria, and no violation is silently dropped.

## Ledger + supervision

Ledger header at T0 (`ledger-contract.md`) with `WIP: builders=<n> reviewers=<n>` sized to
`attention-budget.md` (fix workers are a mutation wave: ≤3 builders, 1 reviewer per 3 builders, with
at least 1 reviewer). Stalls → `liveness-resume.md` WATCH; death → RESUME, while compaction → write
`CONTEXT HANDOFF` then RESUME (ledger-scoped, git-verified). Fixes land via `merge-serialization` with
`reviewed-sha-freshness`.

## Anti-patterns

Declaring CONFORMANT off a green axe run alone (the ~30-40% ceiling means the oracle's silence is not
proof — the un-automatable criteria must be parked, not assumed passing). Shrinking the denominator to
only what axe checks (the frozen surface × WCAG set is the denominator). A fix with no revert-to-violation
negative control (a green oracle over reverted markup proves nothing). Confusing access-it with the
per-diff accessibility lens in `review-it`, or with `attest-it` (a standard's obligation set, not a
surface's rendered violations). Silencing the oracle (empty alt, aria-label stuffing, aria-hidden on
real content, role soup): a clean axe over a worse experience — the build-blind review judges
semantics, not the oracle's silence.

## Related

`review-it` (a bounded per-diff a11y lens, not a surface sweep), `attest-it` (standard-obligation
conformance, not rendered violations), `clean-sweep` (a discovered code backlog); `sandbox-policy`
(rw fix workers), `evidence-manifest` (the revert-to-violation negative control each fix carries).

Bundled copy of `access-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
