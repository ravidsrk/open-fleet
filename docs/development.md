# Developing orca-fleet

[Documentation](README.md) · [Contribution rules](../CONTRIBUTING.md)

This is a Markdown catalog with Python and shell helpers. There is no application server to
start. The validator and tests run locally; Orca is needed when you exercise a live mission.

## Local setup

Use Git, Python 3.11 or newer, and a POSIX shell for the shell examples below. The Python tools
and `unittest` suite use the standard library. CI also runs the suite on Python 3.12 and 3.13.

```bash
git clone https://github.com/ravidsrk/orca-fleet.git
cd orca-fleet
git switch -c codex/improve-setup
python3 --version
python3 scripts/validate.py
```

Keep the full Git history and tags: some tests verify recorded releases and evidence against
older commits. If your clone was shallow or omitted tags, fetch the missing history and tags
before running those checks (`git fetch --unshallow --tags`). In a shallow clone
`scripts/validate.py` fails closed on every proven mission's run-report pin and prints that
remedy; it never skips the pin.

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
| `python3 scripts/gen-badges.py --check` | Verify generated counts, activation callouts and proof summary without writing |
| `python3 scripts/eval.py run --suite routing --threshold 1.0` | Check description-based mission routing |
| `python3 scripts/eval.py run --suite injection` | Run the deterministic VAL-01 prompt-injection and trust-fence drills ([`evals/injection-drills.json`](../evals/injection-drills.json), #560) |
| `python3 scripts/bundle.py --check` | Build in a temporary directory and check bundled references |
| `python3 scripts/release_check.py --fast --skip-github` | Verify the local [Release 1.0 checklist](release-1.0-checklist.md) gates |
| `python3 -m unittest discover -s tests -v` | Run the complete contract and fixture suite |
| `git diff --check` | Catch whitespace errors in the patch |

For a docs edit, get feedback first with:

```bash
python3 -m unittest tests.test_docs_navigation tests.test_wire_docs tests.test_release_status_docs -v
```

Then run the validator and **full suite before committing**, as required by
[AGENTS.md](../AGENTS.md). A focused pass does not replace the full check.

The full suite creates temporary Git repositories and can take several minutes. To run one
CI-sized partition locally, use `python3 scripts/shard-tests.py --shard 1 --of 4`; run all four
partitions for full coverage. `python3 scripts/shard-tests.py --check` verifies the partition.

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
`BEGIN GENERATED` / `END GENERATED` markers.

[`scripts/bundle.py`](../scripts/bundle.py) writes `dist/`, which is ignored by Git. Use its
`--check` mode for validation. Diagram assets have a separate
[generator guide](../assets/diagrams/generator/README.md); a prose correction does not require
regenerating every image.

If you add a test module, add its measured weight to
[`scripts/shard-tests.py`](../scripts/shard-tests.py), following the procedure in its header.

## Local checks and CI

CI adds the reference skill validator, Ruff ([`ruff.toml`](../ruff.toml)), secret scanning, the
coverage floor and the verifier benchmark. Gate environment variables are documented in
[`.env.example`](../.env.example) and [The verify gate](verify-gate.md#native-path--plugin-hooks-set-claude_plugin_root).
Tool versions and hashes live in [`.github/ci-tools.lock`](../.github/ci-tools.lock); job commands
live in [`validate.yml`](../.github/workflows/validate.yml). These extra tools are separate from
the standard-library setup above. A local test pass is one part of PR validation.

Use [Contributing](../CONTRIBUTING.md#commit-and-pr-conventions) for commit and PR conventions.
Describe the reader problem, the resulting improvement, and the checks you actually ran.
