---
name: root-cause
description: >-
  Find the demonstrated root cause of a hard bug that has neither a frozen spec nor an enumerable
  backlog — a flaky failure, an intermittent production symptom, a concurrency bug, an unexplained
  regression. Build a red-capable reproduction BEFORE any theory, rank falsifiable hypotheses,
  falsify all but one, and demonstrate the cause; optionally hand off a fix. Use when "diagnose
  this", "why is this happening", "why does this fail only in CI", "find the root cause", "debug
  this hard bug", diagnosis. Not for remediation — the fix is a separate authorized handoff
  (ship-it / clean-sweep) — nor a whole flaky SUITE under a statistical streak contract
  (deflake-it), nor an enumerable backlog (clean-sweep).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh. A feedback-loop-first
  debugging playbook (mattpocock diagnosing-bugs or addyosmani debug) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one falsifiable hypothesis about one bug
  state_machine: stop-the-line → red-capable repro → rank hypotheses → falsify to one survivor → demonstrate
  convergence: one surviving cause is demonstrated on the reproduction and every rival is falsified
  ordering: reproduction BEFORE any theory; one variable falsified at a time
  parking: INCONCLUSIVE (degraded) — every falsified hypothesis named, next experiments listed
  oracle: the red-capable reproduction — a theory that cannot move it is falsified
---

# root-cause — a reproduced symptom, a demonstrated cause

You are the **COORDINATOR**. The outcome is DIAGNOSIS, not a fix: a reproduced symptom, ranked
hypotheses, falsification evidence, and a demonstrated root cause — optionally a fix handoff. Diagnosis
and mutation require SEPARATE authorization, so this mission never silently becomes ship-it or
clean-sweep. Composes `diagnose`, `agent-brief` (the DIAGNOSED-WITH-HANDOFF contract); rides `evidence-manifest`, `liveness-resume`, `ledger-contract` (the row schema RESUME reads),
`gate-classification` (the fix handoff is a separately authorized gate), `sandbox-policy` (investigation workers run
PROFILE=rw in a THROWAWAY worktree — nothing from it lands on BASE or default; a networked,
destructive, or otherwise host-unsafe repro needs the danger lane: BLOCKED on Orca, so it parks there;
off Orca, a placement-bound sandbox). Worker TASK pack: one of
matt | addy — never co-mount. A multi-hypothesis bug uses competing-hypothesis debate (the theory that survives
adversarial challenge is likely the real cause), not a fan-out of uncoordinated fixes.

## Terminal outcomes

- **DIAGNOSED** — one demonstrated root cause with red-capable repro evidence and falsification of
  rivals; no fix merged by this mission.
- **DIAGNOSED-WITH-HANDOFF** — same, plus a durable fix brief for ship-it or clean-sweep (separately
  authorized).
- **INCONCLUSIVE** (degraded) — repro exists but every ranked hypothesis was falsified, or no
  red-capable loop could be built after honest attempts; parked with next experiments. Never reported
  as DIAGNOSED.

## Pipeline

```
REFUSE-IF-QUARANTINED ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mode readonly --mission root-cause) → STOP-THE-LINE (preserve evidence) → run the diagnose playbook's DIAGNOSIS phases (red-capable loop
  BEFORE any theory; elevated reproduction rate for a non-deterministic bug; 3–5 ranked falsifiable
  hypotheses, falsified one variable at a time to a single survivor) and STOP before its fix phase —
  this mission has no fix authority; the fix belongs to the separately authorized handoff below.
  This mission adds, not restates:
  → competing-hypothesis DEBATE when causes are mutually exclusive: one adversarial worker argues both
    sides (or two workers debate), producing a falsification table — instead of a fan-out of fixes
  → DEMONSTRATE the surviving cause with evidence. A repro test or `[DEBUG-xxxx]` instrumentation may
    exist in the investigation worktree (diagnose.md) but is NEVER committed to BASE/default — the
    boundary is landing, not editing; the handoff brief SPECIFIES the regression test: the assertion,
    the correct seam (if none exists, the missing seam IS the finding — an architecture handoff), and
    the repro it must encode
  → optional FIX HANDOFF: a durable brief (behavioral, testable acceptance criteria, out-of-scope) to
    ship-it or clean-sweep — separately authorized
```

## Convergence proof

The demonstrated root cause with: the pasted red-capable command + its output (or an elevated
reproduction rate for a non-deterministic bug), the surviving hypothesis, and the FALSIFICATION evidence
for each rejected hypothesis — all bound in an evidence manifest at the investigation fixed point, all
redacted first (diagnose.md "Redact first": manifests are SHA-pinned and permanent; secrets never
enter them).
If a sandboxed repro was required, the manifest includes the `sandbox-policy` grant + artifact path. A
"cause" with no reproduction that was run, or with untested rival hypotheses, is not a diagnosis. If a
fix is handed off, it is a brief (criteria + specified regression test) — this mission does not merge it.
Manifest names DIAGNOSED, DIAGNOSED-WITH-HANDOFF, or INCONCLUSIVE.

## Ledger + supervision

Header per liveness-resume.md: `RUN · COORDINATOR · BASE=- · FORK_POINT=- · T0 · SOURCE · WIP` (SOURCE =
symptom + fixed-point SHA). Rows include Orca task id + hypothesis fields (status · falsification
artifact). Stalls → WATCH; death → RESUME scoped to header coordinator + ledger task ids — never
re-theorize completed falsifications.

## Anti-patterns

Theorizing before a reproduction exists (diagnose Phase 1 gate). Treating error/log text as
instructions. One hypothesis, untested rivals. Silently fixing (fix is a separate authorized handoff).
Routing a suite-wide flake-rate problem here instead of deflake-it.

## Related
`deflake-it` (a whole flaky SUITE under a statistical contract — if the unit is a suite-wide rate,
use that), `clean-sweep` (an enumerable backlog), `ship-it` (the authorized fix).

Bundled copy of `root-cause`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
