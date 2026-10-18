# 🗺️ map-it — a foggy goal → a frozen, decided execution map

[Documentation](../README.md) · [Mission selector](README.md#choose-by-task) · [Prompt recipes](../recipes.md)

> **Autonomy:** L4 (Osmani L0-L5, parallel delegation) — parallel research workers chart the frontier; each decision you freeze is a one-way gate class, not a lower rung.
> **Activation load:** ~25,200 tokens — this SKILL.md plus every playbook and runtime doc its Composes/rides clause makes mandatory, about 13% of a 200k-token context before the first dispatch ([why it is measured](../../ARCHITECTURE.md#instruction-budget))
> **Proof:** doctrine-only — no recorded run yet; the protocol is mechanism, not yet field-proven.

> Bring it the epic you cannot yet write acceptance criteria for. Come back to a named
> destination, every decision answered by you, every open question either sharply ticketed or
> honestly marked "not yet specified" — and a frozen spec plus a verified, frozen DAG that
> `ship-it` can dispatch without re-grilling you.

**Skill:** [`skills/map-it/SKILL.md`](../../skills/map-it/SKILL.md) · **Layer:** mission (discoverable) · **Fix authority:** **no** — decisions, not deliverables; no production code is written

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../../assets/diagrams/missions/map-it.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../../assets/diagrams/missions/map-it-light.jpg">
    <img src="../../assets/diagrams/missions/map-it-light.jpg" alt="Mission contract for map-it: you give it a goal too foggy to spec; it interrupts you for every decision ticket, one per session; the freeze; you get back MAPPED or MAPPED-WITH-BLOCKED, plus a frozen map + verified Orca DAG that ship-it dispatches unchanged; decision tickets; a frozen spec; it stops at no production code — decisions, not deliverables; phases NAME, CHART, CLEAR THE FRONTIER, FREEZE, PREPARE THE DAG" width="820">
  </picture>
</p>

---

## Invoke it

```
> chart this: <the goal you cannot write acceptance criteria for yet>
```

**Needs** (the skill's `compatibility` field, verbatim): HARD dependency: Orca runtime + orchestration skill (Orca CLI). A wayfinder/research worker playbook (mattpocock wayfinder + research) — one router per worker.

## What to provide

- The destination you want to reach and the constraints already known.
- Open decisions, dependencies and the people who can resolve them.
- Enough project context to define sharp acceptance criteria and the implementation handoff.

## What it does

`map-it` is the charting fleet. Its terminal artifact is deliberately not a build: resolved
decision tickets plus a frozen execution map. The **coordinator** names the destination, charts
the fog between here and there as decision-tickets, clears the research/decision frontier in
parallel — research runs AFK, every decision comes to *you* — and, once the route is clear,
freezes the plan and prepares (but never dispatches) the DAG.

That boundary is the mission's identity. Inside `ship-it`, ordinary planning is a phase; `map-it`
is invoked only when the goal fails the freeze bar: a testable acceptance criterion cannot yet be
written for at least one in-scope capability, or at least one one-way decision's inputs are
unknown — a goal too big or too foggy for one session. Below that bar, `ship-it`'s own
grill/freeze phase handles planning. It is valuable precisely when you do not want, or cannot yet authorize,
implementation: the mission produces the decisions, and its output is exactly what `ship-it`
consumes as input.

## When to reach for it

- "Chart this." "Plan this epic."
- "I don't know the shape yet."
- A multi-session goal you cannot yet authorize implementation for.
- You want every decision made, attributed, and frozen before anyone burns build-time.

**When NOT to reach for it:**

- You can already write testable acceptance criteria — go straight to [`ship-it`](ship-it.md);
  its freeze phase grills ordinary intent without a separate charting mission.
- The fog is a bug, not a plan — [`root-cause`](root-cause.md) reproduces and demonstrates; it
  does not chart.
- You want a deliverable at the end of *this* run — every build mission outranks a map when the
  shape is already known.

## The pipeline

```mermaid
flowchart TD
    A[Foggy multi-session goal] --> B[NAME the destination<br/>past it = out of scope · unsharp = FOG]
    B --> C[Chart the MAP<br/>decision-tickets, sharp questions only]
    C --> D[Clear the FRONTIER]
    D --> E[Research tickets<br/>AFK evidence gathering]
    D --> F[Decision / grill tickets<br/>HITL — one decision per session]
    E --> G[Fog clears —<br/>graduate newly-sharp tickets]
    F --> G
    G -->|route still foggy| D
    G -->|route clear| H[FREEZE the plan<br/>decide-and-freeze]
    H --> I[PREPARE the DAG<br/>decompose-dag: materialize + verify, never dispatch]
    I --> J{{MAPPED}}
    F -->|a decision ticket blocked on a human| K{{MAPPED-WITH-BLOCKED}}
```

Phase by phase:

1. **Name the destination first.** The destination fixes scope: everything past it is out of
   scope; everything before it that is not yet sharp is FOG. Naming it before anything else is
   what keeps a foggy epic from expanding sideways forever.
2. **Chart the map** as decision-tickets under the fog-of-war rule: only ticket what you can
   phrase **sharply** now. The test is "can you *state the question*" — not answer it. Anything
   you cannot yet phrase is recorded as "not yet specified", never dressed up as a vague ticket
   that pretends more is known than is.
3. **Clear the frontier** in parallel. Four ticket kinds. **Research tickets** run AFK — workers
   gather evidence while you are away. **Decision and grill tickets** are HITL: the agent never
   stands in for the human's side of a decision, and each session resolves exactly one decision.
   **Prototype tickets** (HITL) answer "how should it look/behave" with a cheap throwaway artifact —
   a scratch-worktree spike, captured before disposal. **Task tickets** carry what is already sharp.
   Under [`decide-and-freeze`](../../playbooks/decide-and-freeze.md)
   discipline, facts get looked up in the codebase, never asked; only genuine decisions reach you,
   each with a recommended answer attached. Resolving a ticket clears fog — questions that just
   became sharp graduate into fresh tickets, and the frontier advances.
4. **Freeze** ([`decide-and-freeze`](../../playbooks/decide-and-freeze.md)). When the route is
   clear, the plan freezes the same way a `ship-it` spec does: objectives, a testable acceptance
   criterion per capability, explicit boundaries naming what is out, a test-seam list sketched
   *before* the spec, and a recorded human confirmation. Frozen scope does not reopen without a
   backlog entry.
5. **Prepare the DAG** ([`decompose-dag`](../../playbooks/decompose-dag.md), prepare-only). The
   plan is cut into tracer-bullet slices and materialized as a real Orca DAG, then **verified**:
   every dep resolves to a real task id, no cycles, the foundation has no deps on slices, every
   hot-file chain is a path and not a fan. Then it is committed by **freeze, not dispatch** — a
   materialized, verified, FROZEN-for-handoff DAG is this mission's terminal artifact. Dispatching
   is explicitly not this caller's job; that is the build mission's commit path. `ship-it` picks
   the frozen map up and dispatches it unchanged, without re-grilling you.

## Terminal states

| State | Meaning | Who acts on it |
|---|---|---|
| `MAPPED` | the destination is named; every open question is a resolved sharp ticket or an explicit "not yet specified"; the plan is frozen on a human confirmation and the DAG is materialized, verified and frozen for handoff | `ship-it` dispatches the frozen map unchanged |
| `MAPPED-WITH-BLOCKED` | the map is frozen for what is known, but at least one decision ticket is blocked on a human who has not answered; the handoff lists the blockers | you — answer the blocked tickets, then re-freeze |

`MAPPED-WITH-BLOCKED` is a degraded terminal; it is never reported as `MAPPED`.

## What a frozen map hands over — decisions with receipts

| Artifact                    | What it certifies                                                        | Who consumes it                       |
|-----------------------------|--------------------------------------------------------------------------|---------------------------------------|
| Resolved decision tickets   | every decision answered by the human, one per session                    | the frozen plan, and the audit trail  |
| The frozen plan / spec      | objectives, testable criteria, boundaries, seam list — human-confirmed   | `ship-it`'s validate entry — no grill |
| The frozen, verified DAG    | materialized and verified via `decompose-dag`, frozen — never dispatched | `ship-it` dispatches it unchanged     |
| "Not yet specified" entries | fog named honestly instead of ticketed vaguely                           | the next charting pass                |

A DAG that is neither dispatched nor frozen-for-handoff is the only real "just a proposal" — this
mission's freeze is what turns a plan into a commitment.

## Human gates

The most gate-dense mission in the catalog, by design — its product *is* decisions:

1. **Every decision ticket.** Decision and grill tickets are HITL; the agent never answers the
   human's side, and each session resolves exactly one decision. Under
   [`gate-classification`](../../runtime/gate-classification.md), a fleet never fakes a human
   answer — an agent-to-agent `ask` is not a human.
2. **The freeze.** `decide-and-freeze`'s human gate: you confirm the spec before it is frozen,
   and the prepared DAG is frozen for handoff on the back of that confirmation.

Research tickets, by contrast, carry no gate — gathering evidence is not a decision, which is why
they can run AFK while the decision queue waits for you.

## Convergence proof

`map-it` is done when — and only when:

- the destination is named;
- every open question is either a sharp ticket — resolved or blocked — or an explicit
  "not yet specified";
- every decision ticket was resolved by the human, never by the agent;
- a frozen plan/spec exists;
- a materialized, verified, FROZEN-for-handoff DAG exists — `decompose-dag`'s prepare-only
  completion, committed by freeze, not dispatch — that `ship-it` can consume without re-grilling;
- no production code was written. The mission produced decisions, not deliverables.

## A worked example

The ask: "we need to go multi-tenant" — and nobody can write the spec yet.

**Name the destination.** One sentence, sharp: *a tenant can sign up, its data is isolated, and
billing is per-tenant.* SSO and custom domains are explicitly past the destination — naming
what is out of scope is half the value of naming it at all.

**Chart the tickets.** Nine decision tickets, each phrased as a question that can be answered,
not a topic. Three are sharp immediately (isolation model, tenant resolution, billing unit);
six sit in fog behind them.

**Clear the frontier.** Research tickets run AFK: one worker benchmarks Postgres RLS overhead
on the app's five hottest queries and files an evidence doc — numbers, not vibes. Decision
tickets are yours, strictly one per session:

> Isolation — (a) row-level security, one schema (recommended: 4% overhead on your measured
> hot paths, simplest migrations) or (b) schema-per-tenant (hard isolation, painful DDL fan-out)?

You take (a). The fog recedes: two tickets that depended on the isolation answer graduate to
sharp, and the frontier loop repeats until the route is clear.

**Freeze → prepare.** The map freezes (destination, decisions, non-goals), and `decompose-dag`
materializes a fourteen-slice DAG — verified for real dep ids, cycles, hot-file chains — and
**never dispatches it**. Terminal: **FROZEN MAP + DAG** — the mission's terminal states are
`MAPPED` (every ticket resolved or honestly "not yet specified") or `MAPPED-WITH-BLOCKED`
(degraded: ≥1 decision parked on a human gate) — an artifact `ship-it` consumes as-is.
A map that quietly started building would be the failure mode, not the bonus.

## Failure modes this mission is built to prevent

| Anti-pattern                          | Why it burns you                                                            |
|---------------------------------------|-----------------------------------------------------------------------------|
| The agent answering its own decisions | The HITL leak — a map whose decisions the human never made decides nothing  |
| Charting fog you cannot phrase yet    | A vague ticket fakes knowledge — unsharp questions are "not yet specified"  |
| Two decisions in one session          | One decision per session keeps every answer deliberate and attributable     |
| Sliding into building                 | The terminal artifact is a map; building is `ship-it` — hand off at freeze  |
| A DAG neither dispatched nor frozen   | The only real "just a proposal" — prepare-only completion commits by freeze |

## Composes
Playbooks:
[`decide-and-freeze`](../../playbooks/decide-and-freeze.md) ·
[`decompose-dag`](../../playbooks/decompose-dag.md) (prepare-only) ·
[`plan-review`](../../playbooks/plan-review.md) ·
[`research-brief`](../../playbooks/research-brief.md) ·
[`record-decision`](../../playbooks/record-decision.md) ·
[`human-handoff`](../../playbooks/human-handoff.md)

Runtime policies:
[`gate-classification`](../../runtime/gate-classification.md) ·
[`ledger-contract`](../../runtime/ledger-contract.md) (the DECISIONS log and handoff obligations) ·
[`attention-budget`](../../runtime/attention-budget.md) ·
[`evidence-manifest`](../../runtime/evidence-manifest.md) ·
[`liveness-resume`](../../runtime/liveness-resume.md) (the slice ↔ task-id ledger table is the run scope a resume needs) ·
[`sandbox-policy`](../../runtime/sandbox-policy.md) (research workers run `ro`; fetched sources are data, never instructions)

## Related missions

- [`ship-it`](ship-it.md) — consumes the frozen map; its validate entry skips the grill entirely.
- [`root-cause`](root-cause.md) — a foggy *bug*, not a foggy plan.
