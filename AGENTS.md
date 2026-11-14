# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, Gemini CLI, OpenCode, etc.)
working in this repository.

## What this repo is

**Autonomous fleets** for the [Orca](https://github.com/stablyai/orca) runtime, each named
for an outcome, never for the pack whose technique a worker runs. Read
**[ARCHITECTURE.md](ARCHITECTURE.md)** before adding or changing anything — the whole point of
this repo is a discipline that a careless edit erases.

Three layers, strictly separated:

- **Missions** — `skills/<name>/SKILL.md`. The only discoverable, auto-triggering skills.
- **Playbooks** — `playbooks/<name>.md`. Callable phase protocols a mission injects into a
  worker's TASK. Not skills. They have no frontmatter and never auto-trigger.
- **Runtime** — `runtime/*.md` policies + `runtime/scripts/` + `runtime/providers/`. Orca and
  multi-runtime dispatch/gate/merge/liveness/sandbox mechanics. Missions call these; users never
  invoke them. Runtime control files sit
  beside them: `runtime/pins.json` (upstream pins), `runtime/one-way-doors.json`, and
  `runtime/quarantine.json` — the component quarantine deny-list (#558) that `validate.py`,
  `preflight.py --mission` and `quarantine_check.py` enforce fail-closed. Only a human adds,
  removes or narrows a quarantine entry; an agent never edits it.

Only `skills/` may contain a `SKILL.md`, and no `_`- or `.`-prefixed directory under `skills/` may
hold one. `scripts/validate.py` fails the build if either breaks.

## Intent → mission mapping

| User says… | Mission |
|---|---|
| "build and ship this" / "spec to shipped product" / autonomous build-to-release | [`ship-it`](skills/ship-it/SKILL.md) |
| "close every issue" / "drain the backlog" / "fix everything in this audit" / "the README lies" | [`clean-sweep`](skills/clean-sweep/SKILL.md) |
| "harden this" / "security sweep" / "red team" / "close the security loop" | [`harden-it`](skills/harden-it/SKILL.md) |
| "the app is slow" / "perf budget" / "Core Web Vitals sweep" | [`speed-it`](skills/speed-it/SKILL.md) |
| "update the dependencies" / "upgrade everything" / "framework migration" | [`modernize-it`](skills/modernize-it/SKILL.md) |
| "close the test gap" / "cover the critical paths" / "test debt" | [`prove-it`](skills/prove-it/SKILL.md) |
| "kill the flaky tests" / "deflake the suite" / "flake zero" | [`deflake-it`](skills/deflake-it/SKILL.md) |
| "review this PR" / "is this ready to merge" / read-only verdict | [`review-it`](skills/review-it/SKILL.md) |
| "chart this" / "plan this epic" / "I don't know the shape yet" | [`map-it`](skills/map-it/SKILL.md) |
| "diagnose this" / "why is this happening" / hard intermittent bug | [`root-cause`](skills/root-cause/SKILL.md) |
| "contribute to this project" / "open PRs upstream" / "we only have a fork" | [`oss-contribute`](skills/oss-contribute/SKILL.md) |
| "prove compliance" / "conformance" / "audit-ready evidence" / "SOC 2 / EU AI Act / SSDF" | [`attest-it`](skills/attest-it/SKILL.md) |
| "accessibility" / "a11y" / "WCAG conformance" / "screen reader" / "Section 508" | [`access-it`](skills/access-it/SKILL.md) |
| "Orca updated" / "re-pin the runtime contract" / "policy lags practice" / "dispatch docs are stale" | [`pin-it`](skills/pin-it/SKILL.md) |
| "set the quality bar" / "make CI enforce" / "define our standards" / "bar keeps slipping" | [`floor-it`](skills/floor-it/SKILL.md) |
| "god file" / "architecture erosion" / "refactor the hot path safely" / "interface wider than the implementation" | [`reshape-it`](skills/reshape-it/SKILL.md) |
| "test on a real device" / "works on desktop, breaks on mobile" / "emulator QA" / "on-device bug" | [`field-test-it`](skills/field-test-it/SKILL.md) |
| "migrate the database" / "rename this column safely" / "expand/contract migration" / "backfill this table without downtime" | [`migrate-it`](skills/migrate-it/SKILL.md) |
| "make this operable" / "we were blind during the incident" / "add observability" / "alerts and runbooks" | [`oncall-it`](skills/oncall-it/SKILL.md) |
| "drain the PR queue" / "absorb these community contributions" / "review and merge the open PRs" / "contributor backlog" | [`absorb-it`](skills/absorb-it/SKILL.md) |
| "document this project" / "the API is undocumented" / "docs coverage" / "write the reference docs" | [`document-it`](skills/document-it/SKILL.md) |
| "run this in the cloud" / "set up a sandbox recipe" / "per-workspace environment" / "provision ephemeral dev environments" | [`offload-it`](skills/offload-it/SKILL.md) |

Prefer the most specific mission. When two seem to fit, apply the mission-identity test
(ARCHITECTURE.md): different unit of work, state machine, convergence proof, or an oracle that
changes the proof's shape or its parking classes → different mission.

## Execution model

1. Match the request to a mission (even a 30% match is worth checking).
2. Read the mission's `SKILL.md` in full — it declares its runtime dependency, tooling, gates, and
   the playbooks it composes.
3. Follow the mission's pipeline exactly; each phase runs its playbook.
4. Do not co-mount two upstream packs in one worker (see below).
5. A multi-outcome request ("make this production-ready") is a sequential CHAIN per
   [`runtime/mission-chaining.md`](runtime/mission-chaining.md): declare the sequence and
   allowed terminal states up front; a degraded terminal stops the chain.

## The definition of done is an evidence protocol

Never grade a unit "done" on a worker's narration or trace. Every unit emits a **SHA-bound
evidence manifest** ([`runtime/evidence-manifest.md`](runtime/evidence-manifest.md)) and an
**independent verifier** re-derives the facts from authoritative state:

- the commit exists on the intended base (`git merge-base --is-ancestor`),
- tests pass at that exact SHA in a clean env *(coordinator-run — not verify.py)*,
- the negative control really fails when the change is reverted/mutated,
- mutation units carry a non-empty intent packet and a legal `lighting` value,
- `reviewed_sha == head_sha` (a rebase after review voids it unless the content tree is unchanged —
  `runtime/reviewed-sha-freshness.md`),
- for a ship, the deployed revision equals the reviewed revision *(coordinator-verified)*.

A `worker_done` that says "merged" is a claim to check, not a fact to record.

## One worker-playbook router per worker (hard rule)

Missions draw worker methodology from mattpocock/skills, garrytan/gstack, and
addyosmani/agent-skills. Each ships its own router/meta-skill, and they fight when co-mounted
(clashing command names, competing routing, conflicting TDD philosophies — Addy folds REFACTOR
into the TDD loop, Matt puts it in review). A worker TASK therefore loads exactly **one** pack's
playbooks. Cross-pack composition is fine at the mission level (one worker runs Matt triage,
another runs Addy security-and-hardening); it is never fine inside a single worker. Each mission
states which pack a worker uses in the dispatched TASK.

## Governance is uniform and below the model

- Every decision is classified **mechanical / taste / one-way** and resolved per
  [`runtime/gate-classification.md`](runtime/gate-classification.md). One-way doors always
  override any auto-decide preference; a fleet never fakes a human answer.
- Autonomy tracks the session kind: spawned → auto-pick the recommended option; headless → block
  on the genuinely unanswerable; interactive → prose brief.

## Repository conventions

- Bookkeeping: add a `changelog.d/<slug>.md` fragment, a `docs/runs/index/<run>.json` row or a
  `tests/shard-weights/<module>.json` file; never edit `CHANGELOG.md`'s `[Unreleased]`, the tests
  badge or the generated run table ([`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md), "Bookkeeping files").
- A mission lives in `skills/<name>/` with a `SKILL.md`; `name` frontmatter must equal the folder.
- `description` is 1–1024 chars and includes a "Use when…" trigger; `compatibility` ≤ 500 chars.
- The repo's own claims live under `metadata:` — top level is the agentskills.io allowlist only.
- `metadata.proof:` is required (`doctrine-only` | `self-run` | `external-run`); advancing past
  doctrine-only requires a run report that BINDS (`runtime/scripts/run_report.py`): a `RUN:`
  header, a manifest in the run's own directory, and an inventory that re-hashes at the commit it
  names. Never present a mission as more proven than its evidence. Catalog growth is on a
  proof ratchet in `scripts/validate.py`: a mission beyond the base count must be paid for by
  advancing an existing mission past doctrine-only.
- `metadata` also carries the six identity points (`unit`, `state_machine`, `convergence`,
  `ordering`, `parking`, `oracle`). Two missions declaring the same six fails the build — and so
  does a PARAPHRASE of them (#288): comparison is stemmed and folded through a closed concept
  table: a pair with no divergent point fails, and so does a pair that restates five points and
  diverges on one. A restatement that rewords two or more points outside that table still passes,
  so the six points are reviewed, not just validated.
- Instruction budget (validator-enforced): mission body ≤ 110 lines and frontmatter ≤ 34,
  playbooks ≤ 90, runtime ≤ 160.
- Playbooks and runtime policies are plain Markdown with no frontmatter — never give them a
  `SKILL.md`.
- A mission references the playbooks and runtime policies it composes by BARE name
  (`` `name` `` or `name.md`, never a path), in a "Composes … ; rides …" clause.
  `scripts/validate.py` checks every such name resolves, requires at least one
  backticked name per mission (a bare `name.md` mention is resolved but does not
  count toward that minimum), and checks every `<name>.md` mention — in missions
  AND in playbooks/runtime docs — resolves; case typos and path-prefixed
  references are flagged.
- In a playbook, a backticked playbook name is a CALL: every mission that loads the caller
  composes or defers the callee, or the call is a `read <name>.md` cue at the step that needs it
  (a deferred read those missions inherit). Cite where a rule lives with a bare `name.md` or plain
  words. `tests/test_doctrine_consistency.py` enforces it, with one evidence-manifest §3 class
  per mission, a human-gated FREEZE, deferred reads keyed to real pipeline phases, and a `Recipe:`
  line plus `## Completion` in every playbook.

## Boundaries

- **Always:** read a mission's `SKILL.md` before invoking. Run `python3 scripts/check.py` before
  committing (validate + ruff + the full suite in parallel shards; `--no-suite` for the fast loop,
  `python3 -m unittest tests.test_<name>` for one module).
- **Always:** treat `docs/runs/` artifacts as evidence, not reference — search hides them
  (`docs/runs/.ignore`); read the live code, and a run's `.md` report only for its findings.
- **Always:** keep the three layers separate — new phase logic is a playbook, new dispatch
  mechanics are runtime, only a new *outcome* is a mission.
- **Never:** name a mission for an upstream pack or an ingredient technique.
- **Never:** hardcode secrets in `runtime/scripts/`; env vars only.
- **Never:** grade completion on a trace — bind it to a SHA and verify against authoritative state.

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — the three-layer design, mission-identity test, evidence protocol
- [runtime/evidence-manifest.md](runtime/evidence-manifest.md) — the definition of done
- [README.md](README.md) — the mission catalog
