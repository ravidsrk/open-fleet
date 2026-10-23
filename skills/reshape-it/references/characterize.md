# Playbook — characterize  (pin existing behaviour before changing it)

Recipe: Feathers' characterization tests, sharpened by the repository's own rule that a test which
cannot fail is not evidence. `prove-it` and `reshape-it` both ran this protocol and both wrote it
out; this is the single copy (#290).

## What a characterization net is

A set of tests that assert what the code ACTUALLY does at a named seam — not what it should do.
The net's job is to make a behaviour change visible, so it is only worth what its weakest
assertion is worth.

## The mutation requirement

A passing test proves nothing on its own: it may assert a tautology, or exercise a path no caller
reaches. Each net is earned by a **behaviour-changing, harness-preserving MUTATION** that the net
KILLS:

- flip a boundary, negate a condition, zero a return — the code still COMPILES and the harness
  still RUNS;
- a mutation tool where one fits (`mutmut`, `stryker`, `pitest`, `cargo-mutants`, `go-mutesting`),
  else a hand mutant of the same shape;
- **a compile break is not proof.** A mutant that breaks the build, the imports, or collection
  demonstrates source-SHAPE dependence, not behaviour dependence. It does not count as a kill —
  the verifier refuses it as a stillborn mutant (`verify.py`, evidence-manifest.md §2).

A SURVIVOR means the net is too weak at that seam. Net-building is then its own unit, first; a
surface with no net does not proceed.

## What to record

Per unit, in the evidence manifest's `negative_control` — the field names are the ones `verify.py`
reads, not descriptions of them (evidence-manifest.md §1 carries the full schema):

| Field | Content | Required |
|---|---|---|
| `tool` | `mutmut` / `cosmic-ray` / `stryker` / `pitest` / `cargo-mutants` / `go-mutesting` / `hand` | always |
| `mutant` | the tool's pinned mutant id (`mutmut#7 validate.py:42 '>'->'>='`) | mutation tools; omit for `hand` |
| `artifact` | repo-relative path to the run's output, which must itself evidence the kill | **always** |
| `result` | names the criterion-bound test going RED and the mutant KILLED | always |
| `did` | one line: what was mutated and how | always |
| `command` | the criterion-bound proof command, ONE string | executed lane |

A `hand` mutant carries its unified diff in the `artifact` rather than a `mutant` id, and that diff
must touch the lines the unit changed — the verifier binds hunks, not just files (#280).

`binding_audit` records the coverage method; `metric_contract` carries coverage before/after and
nothing else. The mutation is the proof; the coverage number is context.

## Unit boundary

Landing characterization tests is its OWN mutation unit — own SHA, own negative control, own
review. Never one ledger row binding both the net and the change it was built to protect: that is
the coupling the net exists to break.

## Completion

Every seam in scope has a landed net that KILLS its recorded behaviour-changing mutant (no
stillborn kill), the `negative_control` fields above filled, and no survivor left unparked.
