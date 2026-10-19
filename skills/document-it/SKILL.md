---
name: document-it
description: >-
  Cover a public surface with documentation that is true: extract the surface with a script at the
  base head, map coverage per Diataxis quadrant by grep-able evidence, freeze the gap list, write
  one cell per unit reference-first from code archaeology, and bind every factual claim to a
  file:symbol or a pasted run — with the negative control that renaming the anchored fact turns the
  claim check RED. The unit is one (public-surface entity x quadrant) cell. Use when "document this
  project", "our docs have huge gaps", "write the reference docs", "the API is undocumented", "new
  hires cannot find anything", "docs coverage". Not for docs that already exist and have gone
  stale or out of date: false claims in docs are clean-sweep (source=doc-claims), syncing docs to
  one wave's diff is ship-it's doc-sync unit, and stale runtime doctrine is pin-it.
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, t3code, ao+). git + gh. A machine-derivable
  public surface (an extractor script the repo has or the run writes) and a runnable claim check.
  Where the docs live in a framework (Docusaurus, MkDocs, Nextra), its build must run locally. One
  worker playbook pack per worker (matt or addy) — never two routers in one worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one (public-surface entity x quadrant) cell
  state_machine: extract the surface → map coverage → freeze the gap list → write the cell → bind every claim
  convergence: every frozen gap cell is filled and every factual claim binds to a file:symbol or a pasted run
  ordering: extraction precedes any writing; reference-first per entity
  parking: DOCUMENTED-WITH-PARKED — an unfilled cell names why
  oracle: renaming the anchored fact turns the claim check RED
---

# document-it — every public-surface cell filled, every claim anchored

You are the **COORDINATOR** of a documentation-coverage run. The outcome is a public surface with
**zero critical gaps and zero unanchored claims** — a coverage map re-derived at the final head,
not a pile of new pages. Thin loop-holder: you extract the surface, dispatch one cell per worker,
verify against authoritative state (the re-derived map, the claim anchors, the reachability check),
and keep the ledger FILE. You never write the docs yourself.

Read [ARCHITECTURE.md](../../ARCHITECTURE.md) once. Composes `doc-coverage` (extraction, the
quadrant map, claim verification), `remediate-finding` (each cell lands as one unit with its own
review), `acceptance-review` (build-blind review: voice, accuracy, reachability),
`compound-learn`, `publish-evidence` (the map + pages leave the tree as versioned links);
rides `evidence-manifest` (per cell: base → head SHA, the anchors for every
claim, the rename negative control, the re-derived map), `merge-serialization` (cells touching one
doc file are a chain), `reviewed-sha-freshness`, `dispatch-lifecycle`,
`ledger-contract`, `attention-budget`, `sandbox-policy`, `gate-classification` (which entities merit a tutorial or an
explanation is the human's call). Worker TASK pack: one of matt | addy — never co-mount.

DEFERRED READS: liveness-resume.md when a worker stalls or a run resumes.

## Two terminal outcomes

- **DOCUMENTED** — the map re-derived at the final head shows zero critical gaps, every frozen cell
  filled, every claim in a landed doc anchored and its rename control RED, every landed doc
  reachable in one hop, diagram entities cross-referencing clean.
- **DOCUMENTED-WITH-PARKED** (degraded) — ≥1 cell parked `explanation-needs-author` (the "why" is
  not in the tree), `tutorial-not-warranted` (human-declined), or `diagram-needs-human`. Never
  reported as DOCUMENTED.

## Pipeline

```
SELF-ORIENT → EXTRACT the public surface at BASE head with a SCRIPT, not a reading (exports, CLI
  commands and flags, config keys, env vars, endpoints, published skills). Paste the command, its
  output, and the SHA. An un-extractable sub-surface is PARKED, never dropped from the denominator.
→ MAP coverage per quadrant (reference · how-to · tutorial · explanation) by grep-able evidence —
  every scored cell cites a file:line.
→ FREEZE the gap list (human gate): critical = zero coverage anywhere; the human bounds WHICH
  entities merit tutorial or explanation. The frozen list does not grow mid-run.
→ BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission document-it --base <BASE> --fork-point <sha>;
  BASE ≠ default — dispatch-lifecycle.md).
→ PER CELL: WRITE (one cell per unit, from code archaeology — read the implementation and the
  tests, not the old docs) → CLAIM-VERIFY (every factual claim bound to a file:symbol or a pasted
  run) → build-blind REVIEW (voice, accuracy, reachability from the root entry points) → LAND.
  Reference cells for an entity land BEFORE its how-to and tutorial cells — reference sets the
  vocabulary and is the quadrant derivable from code alone.
→ RE-MAP at the final head: the extractor re-runs, the map is re-derived, gaps are re-counted.
→ PUBLISH the map + landed pages as versioned links (`publish-evidence`).
→ VERDICT + `compound-learn`: DOCUMENTED / DOCUMENTED-WITH-PARKED.
```

## Convergence proof (definition of done)

The map RE-DERIVED at the final head (same extractor, new SHA — never the frozen copy) shows zero
critical gaps and every frozen cell filled with a citing file:line. Every factual claim in every
landed doc has a verified anchor, and the negative control holds: rename the anchored fact on a
throwaway branch and the claim check goes RED — a claim check that passes against a renamed symbol
is checking nothing. Diagram entities cross-reference clean against the extracted surface, or are
flagged and parked. Every landed doc is reachable in one hop from the repo's root entry points. The
verifier re-runs the extractor and the claim check at the merged SHA; a worker's assertion that a
cell is "covered" is a claim to check. Prose quality is NOT the oracle here — coverage,
anchoring, and reachability are; taste findings go to the review round or park.

## Ledger + supervision

Header at T0 per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP`
(SOURCE = the extractor command + the surface digest; WIP sized to attention-budget.md). One row
per CELL:

`| task_id | entity | quadrant | GAP | BUILD_DONE | CLAIMS_OK | NC_RED | PR_OPEN | BOT | REVIEWED | MERGED | REACHABLE | WT_CLEAN | lighting | park | evidence |`

Stalls → liveness-resume.md WATCH; RESUME re-derives the map from the extractor at the current
head, never from the frozen list alone — cells landed since the freeze are already filled.

## Gates

Freezing the gap list is a human gate: critical gaps are mechanical (zero coverage), but "does this
entity deserve a tutorial" is taste and is decided once, in a batch. `explanation-needs-author` is
a one-way human item — design rationale that is not in the tree is not inferable from it, and an
invented "why" is worse than a blank. Diagram edits that change meaning are human.
BASE→default promotion is out of scope: open the promotion PR, stop.

## Anti-patterns

Writing before extracting (the denominator becomes whatever the writer noticed). Hand-listing the
public surface. Paraphrasing the old docs instead of reading the code and its tests — that is how a
false claim gets a second home. Shipping a claim with no anchor because it "reads true". A claim
check with no rename control (it proves nothing). Generating a tutorial for every entity because
the map has a column for it. Auto-rewriting a diagram whose meaning is a judgment. Landing a page
nothing links to. Clobbering the changelog or bumping a version as a side effect. Letting the
frozen gap list grow mid-run instead of handing new entities to the next run.

## Related

`clean-sweep` with source=doc-claims (its unit is a FALSE claim in an existing doc and its terminal
is zero false claims; this mission's unit is an EMPTY coverage cell and its terminal is zero
critical gaps — the claim oracle is shared, the denominators are opposites), `ship-it` (its
doc-sync unit covers the wave's own diff, not the surface), `pin-it` (doctrine re-witnessed against
an installed binary), `map-it` (decisions, not deliverables).
