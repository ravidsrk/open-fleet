# 🧱 floor-it — a written bar that fires

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel wiring and prove-fires workers, one dimension each; freezing the bar is your one-way gate.
> **Activation load:** ~31,800 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 16% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** doctrine-only — no recorded run yet; the protocol is mechanism, not yet field-proven.

> Point it at a repo whose standards live in people's heads. Come back to a committed, numbered
> CONSTRAINTS table where every dimension has a tool, every tool was proven to go RED on an
> injected violation, CI blocks on all of it — and a guard watches the bar itself for quiet
> lowering.

**Skill:** [`skills/floor-it/SKILL.md`](../../skills/floor-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes — `PROFILE=rw` wire workers

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/floor-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/floor-it-light.jpg">
    <img src="../../assets/diagrams/missions/floor-it-light.jpg" alt="Mission contract for floor-it: you give it a repo whose standards live in people's heads; it interrupts you for freezing CONSTRAINTS.md — a one-way gate; headless runs park here; you get back FLOORED or FLOORED-WITH-PARKED, plus CONSTRAINTS.md; one tool per dimension, proven RED; canary PRs; a guard against lowering the bar; it stops at violations injected only on throwaway branches, never on BASE; phases DETECT, FREEZE, WIRE, PROVE-FIRES, ENFORCE, GUARD" width="820">
  </picture>
</p>

---

## Invoke it

```
> set the quality bar
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: Orca runtime + orchestration skill (Orca CLI). git + gh. The target repo's toolchain for each dimension's tool (coverage, linter, perf harness, axe-core…). CI write access on BASE. A worker pack (matt | addy | gstack) — one router per worker.

## What to provide

- The repository's existing counters, quality configuration and CI workflows.
- The dimensions to measure, their baseline commands and proposed thresholds.
- The human who freezes the bar and decides dimensions with no usable measurement tool.

## What it does

`floor-it` installs the quality bar. A **coordinator** reads the stack and drafts the constraint
dimensions with measured current values, then **freezes** them with you — a committed
`CONSTRAINTS.md` table: dimension × threshold × tool × gate job × measured-at-freeze. Workers wire
one machine check per dimension on the integration BASE, each unit build-blind reviewed, and each unit
must **prove it fires before it is reviewed**: the coordinator (never a worker) injects
a violation on a throwaway branch — a deleted test file, a fixture lockfile a scanner reads without
installing, an injected sleep, a stripped alt text, a forbidden import — and the harness goes RED;
revert, GREEN — a harness that stays GREEN is reverted and never lands. After CI enforcement lands, a canary PR per gate must turn CI red and is closed
unmerged. Finally a **guard** — a checked-in validator plus a CI job — fails any diff that lowers a
threshold in `CONSTRAINTS.md` or touches a per-dimension tool-config surface listed in the frozen
table (suppressions, skipped tests, exclusions) without a waiver (a recorded DECISIONS line per
gate-classification).

The unit of work is **one constraint dimension**. The defining property: the bar is written,
numbered, and tool-enforced — prose standards are explicitly not the product.

## When to reach for it

- "Set the quality bar and make CI enforce it."
- "Our bar keeps slipping — catch threshold edits and new suppressions."
- "Define our standards: coverage, security scanning, perf budgets, architecture boundaries."

**When NOT to reach for it:**

- Closing test debt on critical paths — [`prove-it`](prove-it.md) (one dimension, not the bar).
- Journey-level performance budgets with measurement contracts — [`speed-it`](speed-it.md).
- Conformance to an external framework (SOC 2 / EU AI Act) — [`attest-it`](attest-it.md).
- A WCAG conformance sweep over a frozen page set — [`access-it`](access-it.md) (floor-it may wire its axe-core oracle as a CI gate; it never drives the surface).
- A security threat-model loop — [`harden-it`](harden-it.md).

## The pipeline

```mermaid
flowchart TD
    A[repo stack + existing gates] --> B[DETECT<br/>measure current values, draft dimensions]
    B --> C2[BOOTSTRAP integration BASE<br/>preflight · BASE ≠ default branch]
    C2 --> C[FREEZE — one-way gate<br/>CONSTRAINTS.md is the first commit ON BASE · headless run PARKS here]
    C --> D[WIRE per dimension — rw workers<br/>PROVE-FIRES pre-review: throwaway injection → harness RED · revert → GREEN<br/>a harness that stays GREEN never lands]
    D --> E[Build-blind REVIEW → LAND]
    E --> F[ENFORCE in CI on BASE (a reviewed unit) → canary PR per gate<br/>CI must go RED · canary closed unmerged]
    F --> G[GUARD<br/>checked-in validator + CI job against bar-lowering diffs]
    G --> H[REFLECT<br/>untoolable dimensions recorded]
    H --> I{{FLOORED}}
    H --> J{{FLOORED-WITH-PARKED}}
```

## Terminal states

| State | Meaning | Who acts on it |
|---|---|---|
| `FLOORED` | every frozen dimension wired, proven-RED (local + canary PR), enforced in CI; guard in CI; CONSTRAINTS.md committed | nobody — the bar holds |
| `FLOORED-WITH-PARKED` | ≥1 dimension has no measurable tool (parked with the human gate named), or the run parked AT the freeze in a headless session | the named human gate covers that dimension / answers the freeze |

`FLOORED-WITH-PARKED` is a degraded terminal; a chain stops there per
[`mission-chaining`](../../runtime/mission-chaining.md). Advancing requires a one-way human gate
recorded in the ledger, even when the next link's allowlist declares this state tolerable.

## Human gates

**FREEZE is the one-way gate** ([`gate-classification`](../../runtime/gate-classification.md)) —
the thresholds are the product: interactive sessions interview with recommended defaults and you
freeze; **headless / spawned / scheduled runs publish the proposal and PARK at the freeze** —
one-way doors are human-only, never auto-resolved, never defaulted on timeout
([`mission-scheduling`](../../runtime/mission-scheduling.md) already parks at freeze). Editing a
threshold down mid-run is one-way, never mechanical — that is the GUARD's exact target. Violation
injections are coordinator-executed on throwaway branches (never delegated, never on BASE); wire
workers run `PROFILE=rw` ([`sandbox-policy`](../../runtime/sandbox-policy.md)).

## Convergence proof

`floor-it` is done when every dimension in the frozen `CONSTRAINTS.md` is accounted for: a wired
tool whose RED was demonstrated on a throwaway-branch injection and whose GREEN was restored, a
canary PR whose CI ran RED and was closed unmerged, enforcement on BASE, and guard coverage — all
bound to `head_sha` — or PARKED as untoolable with the human gate named. The verifier replays the
RECORDED injection artifacts (archived canary runs and RED/GREEN transcripts); it never injects
fresh violations into landed code. The table never shrank mid-run.

## A worked example

*A run, sketched — the shape of one, not a transcript.*

> set the quality bar

**Detect.** Measured with the repo's existing counters: line coverage 63%, no secret scanning, no
performance budget, a linter already on.

**Freeze (your one-way gate).** Interactive, so you are interviewed with recommended defaults and
you freeze: coverage ≥ 60% and ratcheting up, `gitleaks`, a Lighthouse budget for the two key
journeys, and no lint suppression without a reason. `CONSTRAINTS.md` is the first commit on BASE.
A headless run would have published the proposal and parked here.

**Wire → prove-fires.** One tool per dimension. Before review, the coordinator injects a violation
on a throwaway branch — a fake credential in a fixture, a coverage drop — and each harness goes
RED; reverting the injection goes GREEN. A harness that stayed GREEN would never land.

**Review → land → enforce → guard.** CI on BASE; a canary PR per gate goes RED and is closed
unmerged; a checked-in validator watches for a threshold quietly lowered.

**Reflect.** Accessibility is recorded as untoolable for now (no rendered UI in CI) and parked.
The run ends `FLOORED-WITH-PARKED`.

## Failure modes this mission is built to prevent

| Anti-pattern | Why it burns you |
|---|---|
| A prose bar with no tool per dimension | A wiki page, not a floor |
| A gate admitted to CI before its RED was observed, locally and on a canary PR | A green `continue-on-error` job is a vacuous gate |
| Auto-freezing thresholds in an unattended run | One-way doors are human-only; the run parks at the freeze |
| Injecting violations on BASE or the default branch | Injections live on throwaway branches only |
| Delegating the injection to a worker | It is coordinator-executed, and the security injection is a fixture the scanner reads, never a real known-bad package |
| Editing a threshold down to make a run green | The GUARD's exact target — one-way, never mechanical |
| Letting `speed-it`'s journey budgets stand in for the bar | Journey-level optimization is a different unit; this mission installs the standing repo-wide bar |
| Picking tools before the freeze | DETECT measures with the repo's existing counters; a tool chosen early anchors the bar to the tool |

## Composes
Playbooks:
[`decide-and-freeze`](../../playbooks/decide-and-freeze.md) ·
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`encode-lesson`](../../playbooks/encode-lesson.md) ·
[`compound-learn`](../../playbooks/compound-learn.md) ·
[`human-handoff`](../../playbooks/human-handoff.md)

Runtime policies:
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`merge-serialization`](../../runtime/merge-serialization.md) ·
[`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md) ·
[`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md) ·
[`liveness-resume`](../../runtime/liveness-resume.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) ·
[`gate-classification`](../../runtime/gate-classification.md) ·
[`attention-budget`](../../runtime/attention-budget.md)

## Related missions

- [`prove-it`](prove-it.md) — test debt on critical paths; one dimension of a bar, not the bar.
- [`speed-it`](speed-it.md) — journey-level perf budgets with measurement contracts.
- [`attest-it`](attest-it.md) — external framework obligations, not a self-imposed bar.
- [`access-it`](access-it.md) — the WCAG surface sweep; floor-it may wire its oracle as a CI gate.
- [`harden-it`](harden-it.md) — the security threat-model loop; floor-it's security dimension is a standing gate, not a loop.
- [`pin-it`](pin-it.md) — pins the fleet's own runtime doctrine; floor-it pins the target repo's bar.
