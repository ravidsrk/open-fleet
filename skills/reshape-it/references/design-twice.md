# Playbook — design-twice  (three interfaces before one, and the test strategy that follows)

Recipe: Matt `codebase-design` — DESIGN-IT-TWICE, DEEPENING, and the module glossary. Your first
interface is unlikely to be your best. Where an interface decision is a Lane B fork
(gate-classification.md) — reasonable people would disagree and the fleet must not pick silently —
this playbook is the mechanical way to produce "draft both" instead of arguing about taste.

## Vocabulary (used precisely, not as flavour)

- **Module** — an implementation behind an interface.
- **Interface** — everything a caller must know to use it: signatures, invariants, ordering, error
  modes. Not just the types.
- **Depth / leverage** — how much functionality one entry point buys. A deep module hides a lot
  behind a little. A shallow one makes the caller carry the complexity.
- **Locality** — where a change of a given kind concentrates. Good locality means one kind of
  change touches one place.
- **Seam** — the boundary where an implementation can be substituted.
- **Adapter** — the substitutable implementation behind a seam. **One adapter means a hypothetical
  seam; two means a real one.** Never introduce a port for a single adapter — that is indirection
  wearing a seam's clothes. (Production + test is the usual honest two.)

## 1. Frame the problem space FIRST

Before generating anything: write the constraints any interface must satisfy, the dependencies it
would rely on and their category (below), what sits behind the proposed seam, and a rough code
sketch that makes the constraints concrete. The sketch is a constraint illustration, NOT a
candidate. Publishing the frame first is what stops the three designs from being one design
restated three ways.

## 2. Generate three radically different interfaces (Lane B, mechanically)

Dispatch parallel, isolated workers — each gets the technical frame and the project's own
vocabulary, and none sees another's output. Give each a DIFFERENT forcing constraint:

- minimize the interface: 1-3 entry points, maximum leverage each;
- maximize flexibility: many use cases and extension points;
- optimize the most common caller: the default case is trivial;
- (where dependencies cross a boundary) design around ports and adapters.

Each returns: the interface (types, entry points, invariants, ordering, error modes); a usage
example from the caller's side; what the implementation HIDES behind the seam; its dependency
strategy and adapters; and where its leverage is high and where it is thin.

## 3. Compare on the three axes, then recommend

Present the candidates in full, then contrast them explicitly on **depth** (leverage at the
interface), **locality** (where change concentrates), and **seam placement**. Propose a hybrid where
elements combine well. Then be opinionated: name the strongest and why. The output is a
recommendation plus the rejected candidates with their reasons — both go to the human gate. The
fleet does not pick an interface silently, and the rejected designs are the evidence that the pick
was a choice.

## 4. Test strategy follows the dependency category

Classify every dependency; the category determines how the module is tested across its seam:

| Category | What it is | Strategy |
|---|---|---|
| **In-process** | pure computation, in-memory state, no I/O | always testable through the new interface directly; no adapter |
| **Local-substitutable** | a faithful local stand-in exists (in-process database, in-memory filesystem) | test with the stand-in in the suite; the seam is internal, not on the external interface |
| **Remote but owned** | your own service across a network boundary | define a port at the seam; production adapter for transport, in-memory adapter for tests |
| **True external** | a third party you do not control | inject the dependency as a port; tests use a mock adapter |

Internal seams stay internal: do not widen the interface just because a test wants to reach in.

## 5. Tests: add at the interface, NEVER delete the old oracle

Write new tests at the deepened module's interface — the interface IS the test surface, asserting
observable outcomes rather than internal state, so they survive internal refactors. Upstream's rule
here is "old unit tests on the shallow modules become waste; delete them." **Do not do that.** Those
tests are the pinned oracle proving the behaviour did not change across the reshape; deleting them
removes the only evidence that a behaviour-preserving change preserved behaviour. Old tests are
KEPT and must stay green; a test that genuinely cannot survive because its seam is gone is
retired ONE at a time, each with a recorded replacement assertion at the new interface, through a
human gate — never as a batch cleanup inside the change that made it inconvenient.

## Completion

The problem frame was published before any candidate; at least three genuinely different interfaces
exist, each from an isolated worker with its own forcing constraint; they are compared on depth,
locality, and seam placement with a stated recommendation and the rejected candidates kept; every
dependency has a category and the test strategy that follows from it; no seam was introduced for a
single adapter; every pre-existing test is still present and green, or retired individually with a
recorded replacement and a gate.
