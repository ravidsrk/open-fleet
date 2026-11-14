# Playbook — compound-learn  (REFLECT: capture gotchas for the next session)

Recipe: Orchestra / Factory "Retro" + ETH Zurich finding (LLM-written AGENTS.md hurts; human-
curated helps). After a mission reaches a terminal state, propose durable learnings — never
auto-merge them into the target repo's agent context.

## When (mission REFLECT / final report)

Run once per mission close (ship-it REFLECT, clean-sweep final report, harden-it after CLEAN /
HARDENED-WITH-OPEN-ITEMS). Skip if the run produced zero merged units and zero parked learnings.

## Produce a proposal, not a merge

Write `docs/reports/<run-id>/REFLECTION.md` (or the target repo's equivalent under its docs/):

```
## Surprises
- <what the fleet learned the hard way this run>

## Proposed AGENTS.md / GOTCHAS appends (HUMAN MUST APPROVE EACH LINE)
- STYLE: …
- GOTCHAS: …
- ARCH_DECISIONS: …
- TEST_STRATEGY: …

Categories worth mining every run (the environment-improvement set): navigation pointers (a path
or command a stranger could not find), automated checks (a test/gate that WOULD have caught the
error — route it to the suite, not just the doc), tool economy (token-inefficient or
repeatedly-retried calls worth a script), information access (data the run needed but could not
reach), coding standards (a convention the run had to infer and got wrong), global agent context (a
fact true across every repo the fleet touches, not just this one), and no-op steering (a line in the
worker preamble that changed no behaviour this run — a candidate for DELETION, since the instruction
budget is finite and a line that steers nothing still costs). A learning in none of these categories
is usually noise.

## Prompt / playbook tweaks (fleet-side, optional)
- <one improvement to a TASK preamble — file a backlog item, do not edit open-fleet from here>
```

Rules:
- Prefer the target's existing context file (`AGENTS.md`, `CLAUDE.md`, `docs/GOTCHAS.md`) —
  never invent a second competing file if one exists.
- Keep proposals short (≤ 8 bullets total). Vague "be careful" lines are noise — drop them.
- A correction seen twice is not another agent-context line: read encode-lesson.md and park that unit.
- **NEVER** let a worker `git add` / commit / push into `AGENTS.md` (or equivalent) without a
  recorded human approve of the exact lines. Auto-written agent rules are a known negative.
- Taste-class merges of approved lines may proceed after the human says yes; one-way if the
  repo treats agent-context as protected.

## Search the session index before proposing

Before writing the proposal, search indexed agent sessions for prior runs on the same seams
(`orca search`, guarded: resolve the binary, run the index-status
precheck, skip silently when the app predates search or indexing is off, quote multi-word
queries, redact every snippet before it lands anywhere). A gotcha the index shows recurring
across runs is evidence for the proposal; a gotcha it shows already proposed-and-rejected stays
rejected. The search itself is one line in REFLECTION.md: the phrase searched and the hit count.

## Completion

REFLECTION.md exists beside the run report; every proposed line is either human-approved and
landed, explicitly rejected, or listed in the human-owed queue. No silent AGENTS.md mutation.
