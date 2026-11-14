# Contributing to open-fleet

Contributions are welcome — and this repo is unusually opinionated about what goes where. Read
this page before opening a PR; it will save us both a review round.

For clone/setup commands, a file map and the local test workflow, start with the
[development guide](../docs/development.md). You can edit docs and run catalog checks without a
live Orca runtime. Use this page for the contracts your contribution must preserve.

## The one rule that decides everything else

**A fleet is an outcome, not an ingredient.** Before adding anything, decide which layer it
belongs to:

| You are adding…                                        | It belongs in     | It is a…                       |
|--------------------------------------------------------|-------------------|--------------------------------|
| a new *outcome* with its own definition of done        | `skills/<name>/`  | mission (discoverable skill)   |
| reusable *phase logic* — a phase protocol, even with one consumer | `playbooks/`      | callable protocol, not a skill |
| dispatch/merge/liveness/sandbox *mechanics*            | `runtime/`        | policy, invisible to users     |
| human-facing explanation                                | `docs/`           | documentation                  |

Only `skills/` may contain a `SKILL.md`. Publishing a playbook or runtime policy as a
discoverable skill recreates the routing collisions this repo exists to remove — the validator
fails the build if you try.

## Adding a mission

New missions must clear the **mission-identity test** (see
[ARCHITECTURE.md](../ARCHITECTURE.md)): your workflow is a new mission only if it differs from every
existing mission in at least one of — unit of work, per-unit state machine, convergence proof,
ordering/isolation constraints, parking/failure semantics, the oracle its proof binds to. If it shares all six with an existing
mission, it is a *source* or an *adaptation* of that mission, not a new one. Argue the test
explicitly in your PR description.

A mission PR must include:

1. `skills/<name>/SKILL.md` with:
   - `name:` equal to the folder name (lowercase, hyphens);
   - `description:` 1–1024 chars including a "Use when…" trigger *and* a "Not for…" pointer to
     the neighboring missions it will be confused with;
   - `compatibility:` ≤ 500 chars declaring the runtime dependency and tooling;
   - a **Composes/rides clause** naming, in backticks, every playbook and runtime policy it
     uses (bare names — `` `decide-and-freeze` `` — never paths). At least one backticked name
     is mandatory; the validator rejects a clause it cannot machine-check.
   - a `## Convergence proof` (or definition of done) section and a `## Anti-patterns` section —
     contract tests require both.
   - a `metadata:` block. Top level is the
     [agentskills.io](https://agentskills.io/specification) allowlist and nothing else — every
     repo claim lives under `metadata:`, which is the spec's extension point. `uvx --from
     skills-ref agentskills validate skills/<name>` must say "Valid skill"; CI runs it. A
     top-level extra fails both it and `scripts/validate.py`.
   - `metadata.proof: doctrine-only` — every mission starts there. It advances to `self-run` or
     `external-run` only with a run report that BINDS: a `RUN:` header, a manifest inside the
     run's own `docs/runs/<date>-<mission>…/` directory, and an integrity inventory that
     re-hashes at the commit the header names (`runtime/scripts/run_report.py`) — and, for a
     mutating mission, `waves=<n>` in that header with one measured WIP-curve row per dispatch
     wave (`runtime/attention-budget.md`; the checker refuses a missing, partial or doubled row).
     A report whose artifacts were not retained here is history, not a tier. Do not argue a
     mission is proven in prose; bind the run.
   - `metadata.autonomy:` — the Osmani L0–L5 level.
   - the six identity points — `unit`, `state_machine`, `convergence`, `ordering`, `parking`,
     `oracle`. This is ARCHITECTURE.md's "what makes a mission a mission" test in machine-readable
     form: `scripts/validate.py` fails the build when two missions declare the same six — or merely
     restate them, since comparison is stemmed and a pair with no genuinely divergent point is one
     mission twice. When they differ on only one, it warns if the other five are stated the same
     and fails if any of them is merely reworded. If you cannot fill all six, you are describing a mode of an
     existing mission, not a new one.
   - within the instruction budget: mission BODY ≤ 110 lines and frontmatter ≤ 34 (playbooks ≤ 90,
     runtime ≤ 160). If your mission needs more body, the overflow is probably a playbook.
2. `skills/<name>/evals/evals.json` — `scripts/eval.py validate` checks its schema, and
   `tests/test_evals.py` requires at least one **fixture-backed** case: `files[]` that
   materialize a small repo plus a `workspace_state[]` naming the end state the agent's workspace
   must reach (`exists`, `unchanged`, `matches`, `not_matches` on one `path` or `glob`), read
   straight off the files with no model in between; a `glob` never reads dependency directories
   such as `venv` or `node_modules`, and a regex over an empty match set fails rather than holding
   vacuously. A case with no fixtures must be labeled
   `"narration_only": true`, is graded on its trace alone, and the set of those is frozen in the
   same test. Nothing in `evals/` is proof evidence; it asks whether the mission's *text* steers an
   agent, and only a run report moves `metadata.proof`.
3. An entry in the README mission table and in [AGENTS.md](../AGENTS.md)'s intent → mission mapping.
4. A guide at `docs/missions/<name>.md` following the structure of
   [docs/missions/ship-it.md](../docs/missions/ship-it.md). The guide embeds the mission's contract
   card from `docs/assets/diagrams/missions/<name>.jpg` (dark) and `<name>-light.jpg`, rendered from a
   spec in `docs/assets/diagrams/generator/specs_missions.py` — a test holds guides and assets to parity
   in both directions.
5. An updated `EXPECTED_MISSIONS` set in `tests/test_architecture.py` AND `tests/test_evals.py` —
   the mission set is locked on purpose; changing it is a deliberate act.
6. An activation-load budget in `scripts/mission-load-budgets.json` (`scripts/validate.py` fails a
   mission without one and suggests the number), the mission name among
   `.claude-plugin/plugin.json`'s `keywords`, and a row in
   [docs/getting-started.md](../docs/getting-started.md)'s tooling table
   (`tests/test_doctrine_consistency.py`).

Naming: outcome verbs (`ship-it`, `clean-sweep`), never vendors or techniques. The contract
tests reject mission names containing vendor tokens.

## Adding or changing a playbook

- Plain Markdown, **no frontmatter**, never a `SKILL.md`.
- Write it as a versioned, executable protocol with a checkable completion section — not an
  attribution essay. Name the upstream recipe it adapts in one line at the top.
- Every playbook must be composed by at least one mission, by explicit reference:
  a backticked `` `name` `` inside a Composes/rides clause, or a bare `name.md`
  token. A Related-section backtick is not composition — the orphan test and the
  validator share `explicit_protocol_refs` so they cannot drift.
- If your change alters a completion contract, update every mission that composes it in the
  same PR.

## Changing runtime policies or scripts

Runtime files encode operational lessons that were paid for in broken runs — wrong-base
detection, reviewed-SHA freshness, bot-autofix non-convergence, the stuck-pending watchdog.
Simplifying one because it "seems verbose" is how the lesson gets re-learned. If you can show a
mechanism is genuinely obsolete, remove it *with the story of why it existed* in the commit
message.

`runtime/scripts/` is shared tooling: shell/Python, stdlib only, no secrets (env vars only),
fail-closed exits documented in the header comment.

## Documentation

- `docs/missions/<name>.md` pages follow the ship-it template: an invoke-it line and a Needs
  line copied verbatim from the skill's `compatibility` field (a test keeps them equal), what it
  does, when (and when NOT) to reach for it, a mermaid pipeline, a `## Terminal states` table
  (State · Meaning · Who acts on it, degraded terminals annotated as such), human gates,
  convergence proof, a worked example, failure modes, composes, related. The `## Composes`
  section must name every playbook and runtime policy the SKILL's compose/rides clause declares
  and nothing the SKILL neither declares nor names as a phase-cued read; deferred reads are
  listed separately — contract tests reject drift in both directions.
- Cross-references between catalog files use bare protocol names — the validator flags
  path-prefixed or case-typo'd `<name>.md` references anywhere in `skills/`, `playbooks/`, or
  `runtime/`.
- `README.md` and `docs/` speak to humans; `AGENTS.md`, `SKILL.md`s, playbooks, and runtime
  policies speak to agents. Keep the registers distinct — agent files stay terse and
  imperative.
- Write for a developer completing a task: name the inputs, show the command or prompt,
  explain the expected result, and link the next step. Identify whether the example runs
  in the catalog clone, the target project or the coding-agent session.
- Link new human guides from the [documentation index](../docs/README.md) and the relevant
  entry point. Check file destinations and section anchors; preview tables and diagrams.
- Keep generated callouts and historical run artifacts faithful to their source. Use
  [the generator commands](../docs/development.md#generated-content) for computed values.

## Bookkeeping files: add yours, never edit a shared one

Four records used to take a line from every PR, so with strict up-to-date branches every merge
put every other open PR into conflict. Each is now one file per change, which only your PR
touches; the release cut ([ops guide](../docs/ops.md#release-cut)) folds them in.

| You are… | Add | Never edit |
|---|---|---|
| making a change worth a release note | `changelog.d/<slug>.md`, the entry text ([format](../changelog.d/README.md)) | `CHANGELOG.md` — CI fails a new `[Unreleased]` entry |
| adding a test module `tests/test_<name>.py` | `tests/shard-weights/test_<name>.json` (`python3 scripts/shard-tests.py --measure test_<name> --scale 2`) | another module's weight file, unless your PR is a rebalance |
| filing a run report under `docs/runs/` | `docs/runs/index/<run>.json`, its index row ([format](../scripts/run_index.py)) | the table or the yes-count in `docs/runs/README.md` — the cut renders them |
| changing the test count | nothing | `docs/assets/badges/tests.json` — it is the count at the last release, and the README badge says so |

## Before you open the PR

```bash
python3 scripts/check.py                   # all of the below, the suite in parallel shards; must end "check: GREEN"
python3 scripts/check.py --no-suite        # the fast loop: validate + ruff only
# the steps it runs, one at a time:
python3 scripts/validate.py                # must end: "three-layer separation holds; evals valid."
python3 -m unittest discover -s tests -v   # all contract + validator fixture tests green
ruff check scripts runtime/scripts tests bench evals/demo   # skipped by check.py when ruff is absent
# (CI's version is hash-pinned in .github/ci-tools.lock; rules are in ruff.toml)
```

The validator finishes in a few seconds; the suite takes about an hour serially because it builds
real git repositories, which is why `check.py` runs it as `scripts/shard-tests.py` shards (one per
CPU, at most 8; `--jobs N` to change it). It runs on Linux and macOS; tmux tests use a fake agent and never start your
installed agent CLI. Neither is optional. PRs that fail either
will be asked to fix before review. ruff is CI-only (not required locally). If you add validator behavior, add the negative-path fixture that proves
the new failure branch fires — the suite's standard is that every guard must be demonstrably
capable of failing.

## Commit and PR conventions

- Semantic prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), small logical commits, each
  building alone.
- No `Co-authored-by` or tool-attribution trailers (`Generated-by:`, `Assisted-by:`, a "Generated with <AI tool>" footer). CI enforces this on each PR's own commits; run `python3 scripts/check_trailers.py --base origin/main` locally.
- PR bodies: state the problem, then the solution. If you changed a mission's contract, show
  the before/after of its convergence proof.

## Maintainer ops

Account inventory and the 2 a.m. incident process live in
[docs/ops.md](../docs/ops.md). Contributors do not need that page to open a PR.

## License

By contributing you agree your contributions are licensed under the [MIT License](../LICENSE).
