---
name: prove-it
description: >-
  Give every critical path a test that dies under a behavior-changing mutation. Map the untested
  critical surface (coverage × call-graph of the money/auth/data paths), write characterization
  tests that assert real behavior, prove each earns its keep by failing at its assertion under a
  mutation (harness still runnable — a compile break is not proof), and route surfaced bugs to a
  fix or backlog, looping until every confirmed critical path is mutation-audited. Use when "close
  the test gap", "cover the critical paths", "pin a characterization net", "test debt",
  "add tests before we refactor", characterization/mutation testing, missing coverage. Not for broken tests, nor flake
  eradication (deflake-it), a deterministically failing test (clean-sweep), building features with
  tests from the start (ship-it), or restructuring a module's interface once the net exists
  (reshape-it — its DEEPEN units consume this mission's characterization net).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; a runnable suite +
  coverage tool. A TDD worker playbook (addyosmani or mattpocock) — one router per worker.
metadata:
  proof: self-run
  proof_evidence: docs/runs/2026-09-16-prove-it-self-run.md
  autonomy: L4
  unit: one critical-path behaviour under a mutation-audited test
  state_machine: map the surface → human scope confirm → characterize → mutation-audit → land
  convergence: every path in the frozen critical surface is covered by a test whose mutant is KILLED
  ordering: waves under attention-budget WIP; no ordering constraint between paths
  parking: COVERED-WITH-PARKED — an uncovered path names its blocker
  oracle: a behaviour-changing mutation — the test is proven by killing the mutant, not by passing
---

# prove-it — a mutation-audited test on every critical path

You are the **COORDINATOR**. Here the work CREATES PROOF where no defect finding necessarily exists;
the denominator is a FINITE CRITICAL SURFACE, done is MUTATION-SENSITIVE coverage of it, and bugs
surfaced during characterization spawn a NESTED remediation loop. Composes `characterize`, `build-change`, `design-twice` (choosing the
seam to pin), `remediate-finding` (for surfaced bugs), `acceptance-review`, `runtime-prove`, `compound-learn`;
rides `merge-serialization`, `reviewed-sha-freshness`, `dispatch-lifecycle`, `liveness-resume`,
`evidence-manifest`, `ledger-contract`, `sandbox-policy`, `attention-budget`. Worker TASK pack: one of matt | addy
— never co-mount.

DEFERRED READS, never at activation: mutation-hunt.md at build-blind REVIEW — the reviewer writes its
OWN killer mutant per path (`PROFILE=rw`, scratch clones only, commits nothing), so a builder's audit is never self-graded.

## Two terminal outcomes

- **COVERED** — every path on the confirmed critical surface has a merged, mutation-audited test; every
  surfaced bug fixed-with-test.
- **COVERED-WITH-PARKED** (degraded) — all writable paths mutation-audited, ≥1 surfaced bug parked as
  needs-human (load-bearing quirk / behavior-change decision) or a path can't be tested without a human
  decision. Never reported as COVERED.

## Pipeline

```
MAP critical surface (coverage gaps × call-graph of money/auth/data/external-contract entry points;
  uncovered trivial getters are NOT the mission) → HUMAN scope confirm (bounds the mission)
  → BOOTSTRAP integration BASE (runtime/scripts/preflight.py --mission prove-it --base <BASE> --fork-point <sha
    recorded in the ledger header at BASE creation>; BASE ≠ default — dispatch-lifecycle.md)
  → CHARACTERIZE waves (build-change, characterize): assert REAL expected behavior, and earn each
    net with the mutation `characterize` specifies. Two outcomes:
    · code correct, untested → the test passes; PROVE it per characterize.md, and record the audit's
      `binding_audit` alongside the `negative_control` that playbook defines.
    · test reveals a BUG → SURFACED-BUG sub-loop (remediate-finding). Route small clear fixes in-PR;
      route ambiguous / behavior-changing bugs to PARK needs-human or hand to clean-sweep. Never assert
      the buggy behavior as correct.
  → build-blind REVIEW (acceptance-review + mutation-hunt) → RUNTIME-PROVE (characterization asserts behavior the
    real entry point actually exhibits, not harness-only fiction) → LAND
  → RE-MAP coverage → loop → outcome → REFLECT (`compound-learn`)
```

Waves respect `attention-budget` WIP.

## Convergence proof

Every critical-surface path: a merged test that fails at its assertion under a behavior-changing,
harness-preserving mutation (the audit recorded as `negative_control` + `binding_audit`; the verifier
re-runs the pinned mutant on a sample — ≥10% rounded up, the evidence-manifest §3 floor).
Every surfaced bug: fixed-with-test, or parked with a reason, or handed to clean-sweep. No assertion
weakened to pass (diff-audit). Coverage before/after pasted — but the pass criterion is the
mutation-audit set, not the percent. Manifest names COVERED or COVERED-WITH-PARKED.

## Ledger + supervision

Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (`-` if N/A;
SOURCE = critical-surface digest). Rows include Orca task id + path fields (test · mutation · PR ·
disposition). Stalls → WATCH; death → RESUME scoped to header coordinator + ledger task ids,
git-verified.

## Anti-patterns

Chasing coverage percent (100% with tautological asserts proves nothing). A green test whose mutation
passes (insensitive to the behavior — worse than no test). Accepting a compile break as the mutation
proof. Silently asserting a surfaced bug's wrong behavior as correct. Unbounded surface (needs the
confirmed critical list).

## Related
`deflake-it` (test stability), `clean-sweep` (surfaced bugs go there), `ship-it` (build tests into new work).
