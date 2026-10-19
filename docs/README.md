# orca-fleet documentation

orca-fleet gives coding agents workflows for goals such as shipping a feature, fixing an
audit backlog, or reviewing a PR. Each workflow is a **mission**. You provide the repository,
the goal and its boundaries; the mission coordinates workers and returns a named outcome with
evidence or a list of what still needs attention.

Choose a path based on what you want to do:

| I want to… | Start here | Then read |
|---|---|---|
| Try a mission on my project | [Getting started](getting-started.md) | [Install](install.md), then [prompt recipes](recipes.md) |
| Choose the right mission | [Mission selector](missions/README.md#choose-by-task) | The linked mission guide |
| Understand the result of a run | [Concepts](concepts.md#read-a-run-result) | [Evidence and verification](concepts.md#independent-verification) |
| Fix setup or a stopped run | [Troubleshooting](troubleshooting.md) | The relevant mission's failure modes |
| Change this repository | [Development guide](development.md) | [Contributing](../CONTRIBUTING.md) and [architecture](../ARCHITECTURE.md) |
| Inspect a runtime helper | [Runtime reference](runtime-scripts.md) | Its linked implementation and tests |
| Configure the completion gate | [Gate setup](verify-gate.md#install-paths-and-which-ones-carry-the-gate) | [Trust boundary](verify-gate.md#trust-boundary) |
| Submit evidence from a real run | [Call for runs](call-for-runs.md) | [Run submission guide](run-submission-guide.md) |

Running missions requires Orca and a coding agent. Editing these docs or running the catalog's
local tests requires Git and Python; see [local setup](development.md#local-setup).

## Tutorials and examples

- [Your first review](getting-started.md#your-first-mission-a-review-it-dry-run) — identify a PR,
  supply its spec, and interpret a verdict.
- [Your first feature](getting-started.md#your-second-mission-ship-it-end-to-end) — follow the
  spec freeze, implementation, review and promotion PR.
- [Prompt recipes](recipes.md) — concrete starting points for common development tasks.
- [Anatomy of a run](guides/anatomy-of-a-run.md) — a dated real run, including incidents and
  recovery. Its timings describe that run.
- [Negative-control demo](../demo/negative-control/README.md) — run a local example showing why
  checking a worker's own claim is insufficient.
- [Migration walkthrough](missions/migrate-it.md#populated-sqlite-walkthrough) — the staged
  migration example and its executable fixture.

## Explanations and reference

| Page | What it answers |
|---|---|
| [Concepts](concepts.md) | What are BASE, workers, a manifest, a negative control and a terminal state? |
| [Mission guides](missions/README.md) | What inputs, outcome, approvals and failure modes belong to each mission? |
| [Architecture](../ARCHITECTURE.md) | Why are missions, playbooks and runtime policies separate? |
| [Runtime scripts](runtime-scripts.md) | Which helper handles an operation, and what are its flags and exits? |
| [Multi-runtime & harness guide](runtimes.md) | Which orchestrator providers, coding-agent harnesses and capabilities are supported? |
| [Verify gate](verify-gate.md) | What does the completion hook check, and where is it advisory? |
| [Distribution](distribution.md) | How are installs packaged, and what do proof records establish? |
| [Platform design](platform-ride.md) | Which platform capabilities informed the design at the recorded date? |
| [Compliance provenance](compliance-provenance.md) | What supporting evidence can a manifest carry? |

## For contributors and maintainers

- [Development](development.md) — local commands, generated files, tests and a docs change walkthrough.
- [Contributing](../CONTRIBUTING.md) — the contracts for changing a mission, playbook or runtime helper.
- [Frozen quality bar](../CONSTRAINTS.md) — approved thresholds and their baseline measurements;
  [validate CI](../.github/workflows/validate.yml) holds the current job wiring.
- [Security](../SECURITY.md) — private vulnerability reporting and secret handling.
- [Maintainer ops](ops.md) — account inventory, release commands and incident response.
- [Release checklist](release-1.0-checklist.md) — evidence needed before a 1.0 release.
- [Repository description](about.md) — the canonical text for the GitHub About setting.

## Evidence and history

The [run archive](runs/README.md) records retained runs and explains whether their evidence
binds. A mission's current proof tier lives in its `SKILL.md` and is shown in the
[README catalog](../README.md#the-mission-catalog). `doctrine-only` describes a protocol;
`self-run` and `external-run` require binding reports. A tier is separate from your run's result.

[Research](research/README.md), [reviews](reviews/), [completion records](completion/STATUS.md),
[decisions](DECISIONS.md) and the [changelog](../CHANGELOG.md) explain past findings and choices.
Read them at their recorded date and SHA. Commands quoted in an evidence transcript are a record
of that execution, rather than the current setup procedure. Use the install and development
guides for current instructions.
