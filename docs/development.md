# Developing open-fleet

[Documentation](README.md) · [Contribution rules](../.github/CONTRIBUTING.md) · [Architecture](../ARCHITECTURE.md)

This is a Markdown catalog with Python and shell helpers. There is no application server to
start. The validator and tests run locally; a runtime is needed when you exercise a live
mission: Orca by default, or another provider such as `OPEN_FLEET_RUNTIME=posix` ([runtimes](runtimes.md)).

## The 3-layer mental model

| Layer | Path | In one phrase | Enforced budget (`scripts/validate.py`) |
|---|---|---|---|
| **Missions** | `skills/<name>/SKILL.md` | **What outcome** the fleet converges to (the only discoverable, auto-triggering skills) | Body ≤ 110 lines · Frontmatter ≤ 34 lines |
| **Playbooks** | `playbooks/<name>.md` | **How each phase runs** when injected into a worker `TASK` (no frontmatter, never auto-triggers) | ≤ 90 lines · Must include `Recipe:` and `## Completion` (`tests/test_doctrine_consistency.py`) |
| **Runtime** | `runtime/*.md` + `runtime/scripts/` | **What is enforced below the model** (dispatch, merge train, SHA verification, sandbox, control files) | Policy docs ≤ 160 lines |
| **Tests & Evals** | `tests/` + `evals/` + `bench/` | **Does the contract hold** against mutations, prompt injection, and adversarial trajectories | Stdlib `unittest` + deterministic eval suites |

## 15-minute contributor reading order

Before opening a pull request, read these five files in order (~15 minutes total):

1. **[`ARCHITECTURE.md`](../ARCHITECTURE.md) (5 min)** — The three-layer separation, the six-point mission-identity test, and why workers never self-grade.
2. **[`runtime/evidence-manifest.md`](../runtime/evidence-manifest.md) (3 min)** — The SHA-bound JSON schema every unit emits and `runtime/scripts/verify.py` checks.
3. **[`skills/ship-it/SKILL.md`](../skills/ship-it/SKILL.md) (3 min)** — Canonical example of a mission's frontmatter, `Composes … ; rides …` clause, deferred phase reads, and state machine.
4. **[`playbooks/build-change.md`](../playbooks/build-change.md) (2 min)** — Canonical example of a worker phase playbook (`Recipe:`, single-pack routing, and `## Completion`).
5. **[`CONTRIBUTING.md`](../.github/CONTRIBUTING.md) (2 min)** — Bookkeeping fragment rules (`changelog.d/`, `docs/runs/index/`, `tests/shard-weights/`) and PR trailers.

## Three contribution paths

- **Path A — Tighten a playbook, runtime helper, or doc:** Edit the file, add a positive and negative unit test in `tests/`, add a `changelog.d/<slug>.md` fragment if user-visible, and run `scripts/validate.py` + `unittest`.
- **Path B — Advance an existing mission's proof tier (`doctrine-only` → `self-run` / `external-run`):** Execute a real mission run, retain the artifacts and SHA-256 inventory under `docs/runs/<run>/`, add a `docs/runs/index/<run>.json` row, and verify binding with `python3 runtime/scripts/run_report.py` ([Run submission guide](run-submission-guide.md)).
- **Path C — Propose a new mission:** Must pass the stemmed six-point mission-identity test (`scripts/_identity.py`) against every existing mission **and** pay the catalog proof ratchet by advancing an existing `doctrine-only` mission to `self-run` or `external-run` first.

## Writing within the line budgets (writing for agents)

Mission (`≤ 110` body lines), playbook (`≤ 90` lines), and runtime policy (`≤ 160` lines) caps are hard CI gates (`scripts/validate.py`) designed to protect the coordinator's host prompt budget:

- **Use progressive disclosure (deferred reads):** Keep `T0` activation load small. If a playbook or runtime policy is only needed at a later phase (e.g., Phase 3 review or Phase 4 merge), cite it as `read <name>.md` at that phase step and list it in the mission's `DEFERRED READS` paragraph rather than loading it at startup.
- **Apply the no-op test:** Delete any sentence that tells a frontier model what it already knows by default (generic coding advice, polite filler, restating standard git syntax). Every line in `skills/`, `playbooks/`, and `runtime/` must state a checkable rule, threshold, command, or failure class.
- **Write the procedure, not the model workaround:** State the invariant and the verification command (`verify.py`, `preflight.py`, `spawn_worker.sh`), not brittle prompt patches tailored to one model snapshot.

## Local setup

Use Git, Python 3.11 or newer, and a POSIX shell for the shell examples below. The Python tools
and `unittest` suite use the standard library. CI also runs the suite on Python 3.12 and 3.13.

```bash
git clone https://github.com/ravidsrk/open-fleet.git
cd open-fleet
git switch -c codex/improve-setup
python3 --version
python3 scripts/validate.py
```

Keep the full Git history and tags: some tests verify recorded releases and evidence against
older commits. If your clone was shallow or omitted tags, fetch the missing history and tags
before running those checks (`git fetch --unshallow --tags`). In a shallow clone
`scripts/validate.py` fails closed on every proven mission's run-report pin and prints the
history half of that remedy (`git fetch --unshallow`); it never skips the pin.

You can contribute without installing the catalog into your agent, starting Orca, or logging
into GitHub CLI. Tests exercise runtime operations through fixtures. To test the installed
catalog against a real project, follow [Install](install.md) and [Getting started](getting-started.md).

## Find the right file

| Change | Edit | Check alongside it |
|---|---|---|
| Help a developer understand or use the catalog | `docs/` or `README.md` | Links, examples and the implementation behind factual claims |
| Change a mission's outcome or pipeline | `skills/<name>/SKILL.md` | Its guide, evals and composed protocols |
| Change a reusable phase | `playbooks/<name>.md` | Every mission that composes it |
| Change dispatch, verification or other shared mechanics | `runtime/` | The helper's tests and [runtime reference](runtime-scripts.md) |
| Change catalog validation or packaging | `scripts/` | Validator fixtures or bundle tests |
| Change a threshold or exception | [CONSTRAINTS.md](../CONSTRAINTS.md) and the relevant config | The recorded human decision and floor guard |

Read [ARCHITECTURE.md](../ARCHITECTURE.md) before changing the three-layer design. Only mission
directories under `skills/` contain `SKILL.md`; human guides belong under `docs/`.

## Everyday checks

Run these from the repository root. A successful command exits 0; keep the failure output
when one does not.

| Command | Purpose |
|---|---|
| `python3 scripts/validate.py` | Catalog structure, composition references, budgets, proof declarations and generated freshness (backed by [`scripts/_countlint.py`](../scripts/_countlint.py) and [`scripts/_identity.py`](../scripts/_identity.py)) |
| `python3 scripts/gen-badges.py --check` | Verify generated counts, activation callouts and proof summary without writing. The test count is the last release's: only `--release` (the cut) rewrites it, and `--check --release` checks it |
| `python3 scripts/changelog.py check` | Check the `changelog.d/` fragments the next release cut folds into `CHANGELOG.md` ([format](../changelog.d/README.md)); `preview` prints the next release section |
| `python3 scripts/run_index.py check` | Check one well-formed `docs/runs/index/<run>.json` row per run report; `print` renders today's index; the README holds the rendering from the last cut |
| `python3 scripts/eval.py run --suite routing --threshold 1.0` | Check description-based mission routing |
| `python3 scripts/eval.py run --suite injection` | Run the deterministic VAL-01 prompt-injection and trust-fence drills ([`evals/injection-drills.json`](../evals/injection-drills.json), #560) |
| `python3 scripts/deny_hook_corpus.py` | Differential-test the deny-hook's shell parsing against real bash; `--minimize --write` stores new mismatches as fixtures ([`runtime-scripts.md`](runtime-scripts.md#deny-hooksh), #598). It exits 1 on any mismatch, the documented `boundary` false-denials included: `tests/test_deny_hook_conformance.py` is the check that accepts those |
| `python3 scripts/eval.py run --suite trajectories` | Replay the adversarial worker trajectories through the real guards and print the [results table](adversarial-evals.md) (#602) |
| `python3 scripts/hint_replay.py --check` | Replay the fixed episodic-hint corpus ([`tests/fixtures/hint-replay.json`](../tests/fixtures/hint-replay.json), #605) with hints off, unchecked and checked; fails unless provenance checks retrieve every useful note and leak no stale or poisoned one |
| `python3 scripts/ablation.py prereg` | Check the #606 [ablation pre-registration](experiments/ablation-prereg.md): schema, obligation anchors, the page pinned to the JSON, payloads current. The registration is bound to its live run, so it is checked frozen at the run commit and an edit to a doc it pins no longer makes it stale. `ablation.py run --dry-run --cost-cap-usd 0 --repeats 1` drives the paired pipeline with an inert stand-in (no model, no spend) |
| `python3 scripts/bundle.py --check` | Build in a temporary directory and check bundled references |
| `python3 scripts/wip_curve.py check-prereg` | Check the [WIP-curve pre-registration](experiments/wip-curve-prereg.md) (#604): its digests, its seed commit, and that every oracle fails on the seed and passes on its reference edit |
| `python3 scripts/release_check.py --fast --skip-github` | Verify the local [Release 1.0 checklist](release-1.0-checklist.md) gates. The skipped suite and GitHub checks stand as SKIPs, so a clean run exits 3, not 0; any FAIL exits 1 |
| `python3 scripts/check.py` | One command for the PR checks: validate, ruff and the full suite in parallel shards (`--no-suite` for the fast loop) |
| `python3 -m unittest discover -s tests -v` | Run the complete contract and fixture suite |
| `git diff --check` | Catch whitespace errors in the patch |

For a docs edit, get feedback first with:

```bash
python3 -m unittest tests.test_docs_navigation tests.test_wire_docs tests.test_release_status_docs -v
```

Then run the validator and **full suite before committing**, as required by
[AGENTS.md](../AGENTS.md). A focused pass does not replace the full check.

The suite runs on Linux and macOS. Tests that start real workers (tmux included, when it is
installed) launch a fake agent from a temporary `bin` and put a tripwire ahead of every real
harness on `PATH`, so a test never starts your installed `claude` or other agent CLI.

The full suite creates temporary Git repositories and takes about an hour serially. To run one
CI-sized partition locally, use `python3 scripts/shard-tests.py --shard 1 --of 6`; run all six
partitions for full coverage. `python3 scripts/shard-tests.py --check` verifies the partition,
and `--list` prints it: a few heavy modules run as one unit per TestCase class.

If running tests from an agent terminal that exports `ORCA_TERMINAL_HANDLE`, omit that identity
for the test process so fixture senders can use their own handles:

```bash
env -u ORCA_TERMINAL_HANDLE python3 -m unittest discover -s tests -v
```

## Make a documentation change

1. Follow the reader's task from the [docs index](README.md). Identify what they need to know
   before the next command or decision.
2. Read the source and its tests. Link a factual behavior to its implementation or a retained
   execution. Explain the reason when the repository records it.
3. Put a tutorial, procedure, explanation or reference on the matching page. Link a new page
   from the index and its relevant entry point.
4. State where commands run: the catalog clone, the target project, the shell or the agent
   prompt. Mark illustrative prompts and replaceable values clearly.
5. Preserve generated blocks and historical evidence. Update a current guide when behavior
   changes; keep a dated transcript faithful to the original execution.
6. Run the focused checks, then the required full checks, and review `git diff`.

There is no separate docs-site build. Preview Markdown in GitHub or your editor; GitHub renders
the Mermaid blocks. Local link tests check file destinations, and the mission contract tests
check guide parity. Verify section anchors and command examples as well.

## Generated content

[`scripts/gen-badges.py`](../scripts/gen-badges.py) writes the badge JSON, mission-guide
activation-load callouts, the architecture load table and the README proof summary. If their
source changes, run `python3 scripts/gen-badges.py` and inspect the resulting diff. Keep the
`BEGIN GENERATED` / `END GENERATED` markers. It leaves `docs/assets/badges/tests.json` alone: that
count belongs to the release cut (`--release`), so a PR adding tests never edits it.

Beside the tests badge, two more generated surfaces are written only by the release cut, from
files each PR adds on its own: `CHANGELOG.md`'s dated section from `changelog.d/` fragments
([`scripts/changelog.py`](../scripts/changelog.py)), and the run index in
[`docs/runs/README.md`](runs/README.md) from `docs/runs/index/` rows
([`scripts/run_index.py`](../scripts/run_index.py)). See
[Contributing](../.github/CONTRIBUTING.md#bookkeeping-files-add-yours-never-edit-a-shared-one).

[`scripts/bundle.py`](../scripts/bundle.py) writes `dist/`, which is ignored by Git. Use its
`--check` mode for validation. Diagram assets have a separate
[generator guide](assets/diagrams/generator/README.md); a prose correction does not require
regenerating every image.

If you add a test module, add its measured weight as its own file,
`tests/shard-weights/test_<name>.json`, following the procedure in
[`scripts/shard-tests.py`](../scripts/shard-tests.py)'s header.

## Local checks and CI

CI adds the reference skill validator, Ruff ([`ruff.toml`](../ruff.toml)), secret scanning, the
coverage floor and the verifier benchmark. Gate environment variables are documented in
[`.env.example`](../.env.example) and [The verify gate](verify-gate.md#native-path--plugin-hooks-set-claude_plugin_root).
Tool versions and hashes live in [`.github/ci-tools.lock`](../.github/ci-tools.lock); job commands
live in [`validate.yml`](../.github/workflows/validate.yml). These extra tools are separate from
the standard-library setup above. A local test pass is one part of PR validation.

Use [Contributing](../.github/CONTRIBUTING.md#commit-and-pr-conventions) for commit and PR conventions.
Describe the reader problem, the resulting improvement, and the checks you actually ran.
