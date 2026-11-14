---
name: floor-it
description: >-
  Install a written, numbered, tool-enforced quality bar for a repo: detect the constraint
  dimensions (coverage, security scanning, perf budgets, a11y, architecture boundaries) with
  measured current values, freeze them with thresholds into a committed CONSTRAINTS.md at a human
  gate, wire one machine check per dimension, and prove every gate FIRES — on an injected
  violation in a throwaway worktree before CI, and on a canary PR that must fail CI after — then
  guard the bar itself against quiet lowering. The unit is one constraint dimension. Use when "set
  the quality bar", "define our standards", "make CI enforce", "stop shipping junk", "quality
  gates", "enforce the budget", "constraint-driven", "bar keeps slipping". Not for closing test
  debt (prove-it), journey-level perf optimization (speed-it), a WCAG surface sweep (access-it),
  external-framework conformance (attest-it), or a threat-model loop (harden-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh. The target repo's
  toolchain for each dimension's tool (coverage, linter, perf harness, axe-core…). CI write access
  on BASE. A worker pack (matt | addy | gstack) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one constraint dimension
  state_machine: measure today → set the bar at the measurement → enforce in CI → prove the gate bites
  convergence: every declared dimension has an enforced gate that fails on a deliberate violation
  ordering: none between dimensions; the measurement precedes setting the bar
  parking: FLOORED-WITH-PARKED — an unenforced dimension names its blocker
  oracle: the CI gate itself, proven by a deliberate violation going RED
---

# floor-it — a written bar that fires

You are the **COORDINATOR** of a quality-bar installation. "This repo has a numbered bar, every
dimension is enforced by a tool, and every tool was proven to fire" is a user-facing outcome with
two failure modes this mission exists to kill: a bar that exists only as prose (nothing enforces
it), and a gate never observed RED (it may be vacuous). The bar's thresholds are a one-way door:
the human freezes them, and a headless run PARKS at the freeze rather than defaulting policy into
being. Composes `decide-and-freeze` (FREEZE is the one-way gate), `human-handoff` (the headless-freeze park), `remediate-finding` (wire each
dimension's tool; its failing-first requirement is satisfied by PROVE-FIRES, not a repo test),
`acceptance-review` (build-blind review per wire unit), `encode-lesson`, `compound-learn` (which dimensions resisted
tooling feeds the retro); rides `evidence-manifest` (each dimension carries the injected-violation
RED + restored GREEN + the canary-PR receipt at `head_sha`), `merge-serialization`,
`reviewed-sha-freshness`, `dispatch-lifecycle`, `liveness-resume`, `ledger-contract`,
`sandbox-policy` (`PROFILE=rw` wire workers; violation injections are coordinator-executed, never
delegated), `gate-classification`, `attention-budget`. Worker TASK pack: one of matt|addy|gstack —
never co-mount.

## Terminal outcomes

- **FLOORED** — every frozen dimension has a wired tool, a demonstrated-RED proof (local + canary
  PR), CI blocks on it, and the guard script is itself in CI; CONSTRAINTS.md is committed.
- **FLOORED-WITH-PARKED** (degraded) — ≥1 frozen dimension has no measurable tool (e.g. "code is tasteful")
  and is PARKED, named with the human gate that covers it; or the run parked AT the freeze
  (headless). The bar ships incomplete-but-honest, never with a vacuous check.

## Pipeline

```
DETECT: read the stack (manifests, CI, existing gates) and DRAFT the dimension set with measured
  current values (run the repo's own counters: its coverage runner, its scanner, its perf harness,
  its linters — record the command + the number per candidate dimension) — never ask what the
  repo already answers.
→ BOOTSTRAP integration BASE ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mission floor-it --base <BASE> --fork-point <sha>;
  BASE ≠ default — dispatch-lifecycle.md). EVERYTHING the run produces lands on BASE, including
  the freeze product — CONSTRAINTS.md never commits to the default branch.
→ FREEZE (decide-and-freeze, ONE-WAY): the dimension × threshold × tool × gate-job ×
  measured-at-freeze table becomes CONSTRAINTS.md, committed as the FIRST change on BASE.
  Interactive: interview with recommended defaults; the human freezes. Headless / spawned /
  scheduled: the freeze proposal is published and the run PARKS there (gate-classification:
  one-way is human-only, never auto-resolved or defaulted on timeout).
→ WIRE + PROVE-FIRES per dimension, ONE unit each, IN ORDER (rw workers, remediate-finding):
  wire the smallest harness that measures the dimension on a unit branch off BASE; then, BEFORE
  review, the coordinator (never a worker) injects the violation on a THROWAWAY branch off the
  unit branch — coverage: delete a covered test file · security: a fixture lockfile with a
  known-bad pinned version the scanner reads WITHOUT installing (installing one is a networked
  supply-chain action: the danger lane, BLOCKED on Orca per sandbox-policy — never install) · perf: an injected
  sleep/fixture on a throwaway commit · a11y: an alt/label stripped on a throwaway branch ·
  architecture: a forbidden import on a throwaway branch. The harness MUST go RED on the
  injection and GREEN after revert — that transcript is the unit's failing-first proof
  (remediate-finding's requirement, instantiated for a gate). A harness that stays GREEN on its
  injection NEVER lands: revert the wire commit and PARK the dimension with the gap named.
→ build-blind REVIEW (acceptance-review) → LAND (merge-serialization with reviewed-sha-freshness).
→ ENFORCE: CI jobs on BASE block on the wired gates, cheapest first — the CI change is itself a
  reviewed unit on the same train. Then prove the CI path: one canary PR per gate carrying its
  injection — CI must go RED; the canary is closed unmerged.
→ GUARD: land `floor_guard.py` in the target repo's CI on BASE (`runtime/scripts/` is THIS
  catalog's path — vendor the script) — a reviewed unit like the
  others: any diff that lowers a threshold in CONSTRAINTS.md or touches a dimension's frozen
  tool-config surface (suppressions, skipped tests, exclusions) fails without a recorded DECISIONS
  waiver (gate-classification). The guard is owned by the repo (a CI job), not the terminated
  mission.
→ REFLECT (compound-learn): untoolable dimensions and their human gates recorded.
→ VERDICT: FLOORED, or FLOORED-WITH-PARKED with the register (untoolable dimensions · freeze park).
```

## Convergence proof (definition of done)

Every dimension in the frozen CONSTRAINTS.md is accounted for: a wired harness whose RED was
demonstrated on its throwaway-branch injection BEFORE review (GREEN after revert), landed through
the review train — a harness that stayed GREEN on its injection was reverted, never merged — then
enforced on BASE with a canary PR whose CI ran RED and was closed unmerged, plus guard coverage —
all bound to `head_sha` in the manifest — or PARKED as untoolable with the human gate named. The
canary receipt lands in the manifest's `commands[]` (the captured `gh run` invocation + the CI
conclusion RED, exit code recorded — verify.py's commands contract), and the verifier replays the
RECORDED injection artifacts (the archived canary run and the throwaway RED/GREEN transcripts);
it never injects fresh violations into landed code (evidence-manifest §2). The table never shrank
mid-run; a dimension dropped for convenience is a finding, not an edit.

## Ledger + supervision

Ledger header at T0 (`ledger-contract.md`) with `WIP: builders=<n> reviewers=<n>` sized to
`attention-budget.md`. Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP`
(`-` if N/A; SOURCE = the frozen CONSTRAINTS digest). One row per dimension: id, threshold, tool,
local RED/GREEN transcripts, canary-PR run url, CI job, verdict — PLUS one row each for the
ENFORCE and GUARD units (reviewed mutation units with their own build/review/merge flags; resume
reads flags, not prose). FREEZE blocks on the human in interactive sessions and PARKS headless;
WIRE waves run ≤3 builders. Stalls → `liveness-resume.md` WATCH; death → RESUME (ledger-scoped,
git-verified).

## Anti-patterns

A prose bar with no tool per dimension (a wiki page, not a floor). A gate admitted to CI before
its RED was observed — locally AND on a canary PR (a green `continue-on-error` job is a vacuous
gate). Auto-freezing thresholds in an unattended run (one-way doors are human-only; PARK instead).
Injecting on BASE or the default branch (injections live on throwaway branches only). Delegating
the injection to a worker (coordinator-executed; the security injection is a fixture the scanner
reads, never an install of a known-bad package). Editing a threshold down to make a run green —
the GUARD's exact target, one-way, never mechanical. Letting speed-it's journey budgets substitute
(journey-level optimization is a different unit; floor-it installs the standing repo-wide bar).
Picking tools before the freeze (DETECT measures with the repo's EXISTING counters; the freeze
selects the gate tool — a tool chosen earlier anchors the bar to the tool).

## Related

`prove-it` (test debt on critical paths — one dimension, not the bar), `speed-it` (journey perf
budgets with measurement contracts), `access-it` (a WCAG surface sweep — floor-it may wire its
oracle as a CI gate, never drives the surface), `attest-it` (external framework obligations),
`harden-it` (threat-model loop), `pin-it` (pins the fleet's own runtime doctrine; floor-it pins
the target repo's bar).

Bundled copy of `floor-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
