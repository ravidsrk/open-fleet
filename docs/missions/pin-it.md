# 📌 pin-it — doctrine that matches the binary

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel re-witness probes, one claim each, against the installed binary; doctrine patches land through the normal review + merge gates.
> **Activation load:** ~31,900 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 16% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** doctrine-only — it ran twice against Orca 1.4.200 ([PARTIAL-WITNESS](../runs/2026-09-12-runtime-repin/), [PINNED-WITH-PARKED](../runs/2026-09-13-pin-it-266/)) and once against 1.4.203 ([PINNED-WITH-PARKED](../runs/2026-09-16-pin-it-416/)), but no run's tier is re-derivable here; the protocol is mechanism, not yet field-proven.

> Point it at a freshly upgraded Orca runtime — or at the queasy feeling that the dispatch docs
> describe a binary you no longer have. Come back to a doctrine where every surviving mechanics
> claim carries a receipt captured from the installed binary, and every removed claim carries an
> archived refutation proving it now fails.

**Skill:** [`skills/pin-it/SKILL.md`](../../skills/pin-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** yes — doctrine patches, `PROFILE=rw` workers

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/pin-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/pin-it-light.jpg">
    <img src="../../assets/diagrams/missions/pin-it-light.jpg" alt="Mission contract for pin-it: you give it runtime doctrine and the installed Orca binary; it interrupts you for probes that are one-way — paid, remote, or human-only; you get back PINNED or PINNED-WITH-PARKED, plus a receipt per claim; an archive of refuted claims; doctrine patched with citations; it stops at a substrate failure never rewrites doctrine; phases FREEZE, RE-WITNESS, CLASSIFY, PATCH, LAND" width="820">
  </picture>
</p>

---

## Invoke it

```
> Orca updated — re-pin the runtime contract
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: Orca runtime + orchestration skill (Orca CLI) — the binary under audit; `orca skills get <name>` must work, and re-witness probes run against the live local runtime from a live Orca terminal. git. A worker playbook pack (mattpocock, addyosmani, gstack) — one router per worker.

## What to provide

- The installed Orca version and the runtime claims that may have drifted.
- Access to the relevant hosts and surfaces needed to witness each claim.
- Owners for remote, paid or interactive probes the session cannot perform.

## What it does

`pin-it` re-pins the runtime contract. A **coordinator** freezes the *claim inventory* — every claim
about the installed binary's mechanics in `runtime/*.md`, `runtime/scripts/`, and mission dispatch
preambles (command shapes, receipt fields, lifecycle rules, error codes). Fleet-policy invariants
(BASE ≠ default, ledger flags, reviewed-SHA freshness) are deliberately **out of scope** — the
repo's own gates enforce them and the binary will not reject them. It then loads the version-matched
guides the binary serves (`orca skills get …`) and **re-witnesses** each claim by replaying it from
a live Orca terminal, capturing the verbatim receipt. Claims classify CURRENT, STALE, SUPERSEDED, or
BLOCKED-BY-SUBSTRATE (a failed probe precondition — no sender terminal, expired credentials — says
nothing about the mechanism), purely from receipts; stale doctrine is patched per claim by rw
workers, and a claim can only be *deleted* with a refutation receipt — the old shape demonstrated
failing.

The unit of work is **one mechanics claim**. The defining property: the version-matched guide is a
*hypothesis* about the binary, never the proof — guides drift too, so classification runs on
receipts alone.

## When to reach for it

- "Orca updated overnight — re-pin the runtime contract."
- "A receipt shape appeared in a field run that the runtime docs don't describe."
- "Our dispatch docs are stale; make them true against the installed binary."

**When NOT to reach for it:**

- Dependency or framework upgrades with the repo's own suite as oracle — [`modernize-it`](modernize-it.md).
- A falsifiable prose-claims backlog (README lies) — [`clean-sweep`](clean-sweep.md) `source=doc-claims`.
- A per-diff merge verdict — [`review-it`](review-it.md).

## The pipeline

```mermaid
flowchart TD
    A[runtime policies + scripts + preambles] --> B[FREEZE claim inventory<br/>digest-locked denominator · CLI version recorded]
    B --> B2[BOOTSTRAP integration BASE<br/>preflight · BASE ≠ default branch]
    B2 --> C[LOAD version-matched guides<br/>orca skills get — hypothesis, not proof]
    C --> D[RE-WITNESS each claim<br/>from a live Orca terminal; control-plane probes in a scratch worktree + teardown]
    D --> E[CLASSIFY per claim<br/>CURRENT · STALE · SUPERSEDED · BLOCKED-BY-SUBSTRATE — from receipts only]
    E --> F[PATCH — rw workers<br/>one claim per unit · delete needs a refutation receipt]
    F --> G[Build-blind REVIEW → LAND<br/>every edited line traces to a receipt]
    G --> H{{PINNED}}
    G --> I{{PINNED-WITH-PARKED}}
```

## Terminal states

| State | Meaning | Who acts on it |
|---|---|---|
| `PINNED` | every claim in the inventory is CURRENT with a live receipt; patches receipt-backed at the merged SHA | nobody — doctrine is true |
| `PINNED-WITH-PARKED` | claims needing a surface the session lacks (remote host, paid tier, human-only action, an unfixable-in-session precondition) are PARKED, each named with the exact probe it waits on | the named owner runs the probe |

`PINNED-WITH-PARKED` is a degraded terminal; a chain stops there per
[`mission-chaining`](../../runtime/mission-chaining.md). Advancing requires a one-way human gate
recorded in the ledger, even when the next link's allowlist declares this state tolerable.

## Human gates

Parked claims are one-way items only when the probe itself is one-way (a paid/remote/human-only
surface) under [`gate-classification`](../../runtime/gate-classification.md) — the fleet never
marks such a claim current. A probe whose *precondition* failed (no live Orca terminal, untrusted
worktree, expired credentials) is `BLOCKED-BY-SUBSTRATE`: the precondition is fixed and the probe
re-run — a substrate failure is never evidence about the mechanism, and never rewrites doctrine.
Control-plane probes (run-create, worker-start, worktree create) mutate local Orca state and run
in a scratch Orca worktree with full teardown (settle the run, release workers, remove the
worktree) per the SKILL's sandbox lane.

## Convergence proof

`pin-it` is done when every claim in the frozen inventory is accounted for: CURRENT with a captured
receipt, PATCHED citing its receipts, REMOVED with an archived refutation receipt, or PARKED with
the exact probe it waits on. For doctrine (no test suite binds the prose), the evidence-manifest §1
negative control maps to the claim level: the pre-patch refutation receipt — the old text's probe
demonstrated RED against the live binary — is archived per patched/removed claim and re-run by the
verifier post-merge; a patch whose old text still probes GREEN at `head_sha` is not proven.
Receipts name the CLI version they were captured from; the verifier re-derives a ≥10% sample by
re-running probes at `head_sha`. The inventory never shrank mid-run, and the repo gates (validator,
tests) are green at the landing SHA.

## A worked example

*A run, sketched — the shape of one, not a transcript.*

> Orca updated — re-pin the runtime contract

**Freeze.** The claim inventory — every mechanics claim in `runtime/*.md` — is digest-locked and
the installed CLI version recorded.

**Load guides.** `orca skills get` fetches the version-matched guides: a hypothesis about the
binary, never proof.

**Re-witness.** Each claim is replayed from a live Orca terminal; control-plane probes run in a
scratch worktree with full teardown.

**Classify from receipts.** `CURRENT` (the `worker_done` shape still matches), `STALE` (a flag
renamed), `SUPERSEDED` (a command removed), `BLOCKED-BY-SUBSTRATE` (a probe that needs a second
datadir this host does not have).

**Patch → review → land.** One claim per unit; a deletion carries its refutation receipt; every
edited line traces to a receipt. The run ends `PINNED-WITH-PARKED`, the blocked probes named with
their precondition. The 2026-09-13 run against Orca 1.4.200 had exactly this shape — its report
is in the [run archive](../runs/2026-09-13-pin-it-266/).

## Failure modes this mission is built to prevent

| Anti-pattern | Why it burns you |
|---|---|
| Classifying from the version-matched guide without replaying the claim | Guides drift too |
| Classifying from a substrate-failed receipt | `BLOCKED-BY-SUBSTRATE` is a precondition verdict, never evidence about the mechanism |
| Putting fleet-policy invariants in the inventory | They are preflight- and verify-enforced; the binary cannot reject them |
| Wholesale doctrine rewrites ("modernise the page") | The unit is the claim |
| Dropping a claim because its probe is awkward | That is a park, and it is named |
| Shrinking the inventory mid-run | The denominator is frozen |
| Marking doctrine current because a run "worked" | A run that succeeded through an undocumented fallback is evidence for drift, not against it |
| Control-plane probes without teardown | Orphaned runs, terminals and worktrees in the local Orca state |

## Composes
Playbooks:
[`remediate-finding`](../../playbooks/remediate-finding.md) ·
[`acceptance-review`](../../playbooks/acceptance-review.md) ·
[`compound-learn`](../../playbooks/compound-learn.md)

Runtime policies:
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`merge-serialization`](../../runtime/merge-serialization.md) ·
[`reviewed-sha-freshness`](../../runtime/reviewed-sha-freshness.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) ·
[`liveness-resume`](../../runtime/liveness-resume.md) ·
[`gate-classification`](../../runtime/gate-classification.md) ·
[`dispatch-lifecycle`](../../runtime/dispatch-lifecycle.md) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) ·
[`attention-budget`](../../runtime/attention-budget.md) ·
[`orca-pin`](../../runtime/orca-pin.md)

## Related missions

- [`modernize-it`](modernize-it.md) — dependency/framework upgrades; its oracle is the repo suite, not runtime receipts.
- [`clean-sweep`](clean-sweep.md) — a findings backlog; its doc-claims mode checks prose against repo state, not mechanics against a binary.
- [`review-it`](review-it.md) — a bounded per-diff verdict, no fix authority.
