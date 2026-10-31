# open-fleet Documentation Hub

**open-fleet** provides autonomous, outcome-driven engineering workflows (**missions**) for coding agents across [Orca](https://github.com/stablyai/orca) and the [open-fleet Runtime Provider Interface (RPI)](runtimes.md). You supply a bounded engineering goal; a coordinator decomposes the work, dispatches isolated workers, and verifies every unit against git, test execution, and a negative control before reporting completion.

---

## Quick navigation by task

| I want to… | Start here | Next step |
|---|---|---|
| **Install `open-fleet` and run my first mission** | [Install guide](install.md) | [Getting started walkthrough](getting-started.md) |
| **Roll out `open-fleet` on a greenfield or brownfield repo** | [Greenfield vs. Brownfield adoption guide](adoption-guide.md) | [Mission catalog & selector](missions/README.md#choose-by-task) |
| **Pick the right mission for an engineering job** | [Mission catalog & selector](missions/README.md#choose-by-task) | [Copy-ready prompt recipes](recipes.md) |
| **Compare `open-fleet` with `gstack`, `agent-skills`, `mattpocock`, & `superpowers`** | [Ecosystem comparison & pack composition](comparison.md) | [Concepts & glossary](concepts.md#one-router-per-worker) |
| **Run without the Orca app (`posix`) or on another orchestrator** | [Multi-runtime & harness guide](runtimes.md) | [Provider & harness certification](certification.md) |
| **Understand what a run produces and what its verdict proves** | [Concepts & glossary](concepts.md#read-a-run-result) | [Anatomy of a real run](guides/anatomy-of-a-run.md) |
| **Wire or debug the native completion gate (`verify-gate.sh`)** | [Verify gate & trust boundary](verify-gate.md) | [Negative-control demo](../evals/demo/negative-control/README.md) |
| **Diagnose a stalled worker, gate block, or setup error** | [Troubleshooting](troubleshooting.md) | [Runtime scripts CLI reference](runtime-scripts.md) |
| **Edit missions, playbooks, or docs and run local tests** | [Local development](development.md) | [Contributing guide](../.github/CONTRIBUTING.md) · [Architecture](../ARCHITECTURE.md) |
| **Submit evidence from a real mission run** | [Call for runs](call-for-runs.md) | [Run submission guide](run-submission-guide.md) |

---

## Tier 1 — User & Operator Guides (Tutorials & How-Tos)

Step-by-step tutorials, installation procedures, team rollout playbooks, prompt recipes, and operational guides for running missions on your repositories (organized by [Diátaxis](https://diataxis.fr/) quadrant).

| Guide | Quadrant | What it covers |
|---|---|---|
| **[Getting started](getting-started.md)** | Tutorial | End-to-end walkthrough of your first read-only `review-it` run and your first `ship-it` build, where evidence lands, human gates, and per-mission CLI prerequisites. |
| **[Install](install.md)** | How-To | Comparison and setup instructions for symlink installs (`sh scripts/install.sh`), the Claude Code plugin, non-Claude coordinator hosts, anti-stacking rules, completion-gate hook wiring, and `dist/` bundles. |
| **[Adoption guide (Greenfield vs. Brownfield)](adoption-guide.md)** | How-To | Day 0 greenfield setup and a 4-phase incremental brownfield rollout (Zero Production Changes → Stabilize the Oracle → Bounded Drains → Full Delivery). |
| **[Mission guides](missions/README.md)** | Reference / Catalog | Deep-dive reference for every mission grouped by job-to-be-done: inputs, phases, terminal states, observable `"It's working if…"` behavioral tells, human gates, and failure modes. |
| **[Prompt recipes](recipes.md)** | How-To | Copy-ready prompts with concrete inputs, acceptance criteria, and stop conditions across all mission categories and multi-mission chains. |
| **[Multi-runtime & harness guide](runtimes.md)** | How-To / Ref | Running missions across 14 orchestrator providers (`orca`, standalone `posix`, `overstory`, `t3code`, `ao`, `superset`, `gastown`, `worktrunk`, `jcode-swarm`, `emdash`, `vibe-kanban`, `paperclip`, `multiclaude`, `openhands`) and 14 CLI coding-agent harnesses (10 with verified headless `ro` and `rw` launches; `cursor`, `antigravity`, `grok`, and `droid` `rw`-only where a provider launches them) plus the `openhands` SDK agent, cross-harness loader quirks, and harness porting checklist. |
| **[Anatomy of a run](guides/anatomy-of-a-run.md)** | Walkthrough | Hour-by-hour trace of a recorded multi-worker run, including worker dispatch, verification failures, and recovery. |
| **[Troubleshooting](troubleshooting.md)** | How-To | Symptom → Cause → Fix reference for installation issues, stacked-install conflicts, context compaction recovery, model cyber-safeguard refusals, preflight errors, stalled workers, and verification gate rejections. |

---

## Tier 2 — Architecture, Verification & Technical Reference (Explanations & Reference)

Conceptual explanations, ecosystem comparisons, security boundaries, and exact CLI/schema specifications for how `open-fleet` enforces correctness below the model.

| Document | Quadrant | What it covers |
|---|---|---|
| **[Concepts & glossary](concepts.md)** | Explanation | Core mental model and ubiquitous-language dictionary (`_Avoid_:` synonyms): integration `BASE`, coordinator vs. workers, evidence manifests, negative controls, one-router-per-worker, gate classification, and proof tiers. |
| **[Ecosystem comparison & pack composition](comparison.md)** | Explanation | How `open-fleet` composes `mattpocock/skills`, `garrytan/gstack`, and `addyosmani/agent-skills`, how it relates to `obra/superpowers` and `EveryInc/compound-engineering-plugin`, and when to use a single-session skill vs. an autonomous fleet. |
| **[Architecture](../ARCHITECTURE.md)** | Explanation | The strict three-layer separation (`skills/`, `playbooks/`, `runtime/`), the six-point mission-identity test, and activation-load budgets. |
| **[Verify gate](verify-gate.md)** | Reference | How `runtime/scripts/verify-gate.sh` and `runtime/scripts/verify.py` enforce completion, every gate input under its `OPEN_FLEET_*` name and legacy `ORCA_*` alias, negative-control replay (`OPEN_FLEET_EXECUTE_NC` / `ORCA_EXECUTE_NC`), and the off-worker trust boundary. |
| **[Runtime scripts](runtime-scripts.md)** | Reference | CLI reference (flags, JSON outputs, and exit codes) for the runtime helpers in `runtime/scripts/` and the operator configuration files in `runtime/`; the verification tools (`preflight.py`, `verify.py`, `verify-gate.sh`, `evidence-run.py`, `dispatch-sign.py`, `inventory.py`, `run_report.py`, `proof_status.py`) are indexed to their dedicated guides. |
| **[Provider & harness certification](certification.md)** | Reference | Certification matrix across orchestrator providers and coding-agent harnesses, plus reproducible first-run harnesses. |
| **[Distribution & packaging](distribution.md)** | Reference | Enforced vs. observed prerequisite pins, self-contained `dist/` bundle semantics, and ecosystem indexer compatibility. |
| **[Listing kit](distribution-kit.md)** | How-To | Paste-ready marketplace copy for H-02 (#235): per-aggregator blurbs led by the `proof:` framing, submission URLs, and the replacement buildwithclaude blurb. |
| **[Compliance provenance](compliance-provenance.md)** | Reference | What an evidence manifest's provenance block can and cannot support in an audit (EU AI Act Art. 12/50 applicability, the offline retention receipt); naming SOC 2 or NIST SSDF in a manifest establishes no conformance. |
| **[A2A AgentCard export](a2a-export.md)** | Reference | Exporting mission metadata to Agent-to-Agent (A2A) protocol AgentCards and validating against the pinned schema. |
| **[Adversarial trajectory evals](adversarial-evals.md)** | Reference | Red-team trajectory evaluations testing whether runtime guards hold against prompt-injected worker instructions. |
| **[Platform capabilities](platform-ride.md)** | Explanation | A dated ride-vs-keep snapshot of which Claude Code, Agent SDK, MCP, and Orca primitives `open-fleet` rides vs. keeps as its differentiator, plus the platform absorption-risk register. |

---

## Tier 3 — Contributors, Maintainer Ops & Evidence Archives

Guides for developing `open-fleet`, cutting releases, and inspecting retained run evidence, benchmarks, and historical design records.

### Contributing & Maintenance

- **[Local development](development.md)** — Running `validate.py`, contract tests, eval suites, diagram wiring, and badge generators locally with zero external dependencies.
- **[Contributing](../.github/CONTRIBUTING.md)** — Rules for modifying missions, playbooks, runtime scripts, and bookkeeping fragments (`changelog.d/`, `docs/runs/index/`, `tests/shard-weights/`).
- **[Frozen quality bar](../CONSTRAINTS.md)** — Enforced CI thresholds, the floor-guard surface, and ratchet baselines ([CI workflow](../.github/workflows/validate.yml)).
- **[Security policy](../.github/SECURITY.md)** — Vulnerability disclosure process and secret-handling rules.
- **[Maintainer ops](ops.md)** — Account inventory, maintainer roles, the merge gate, release cut and publishing, and incident response. (Weekly pin probes: [`runtime/orca-pin.md`](../runtime/orca-pin.md); component quarantine: [`quarantine_check.py`](runtime-scripts.md#quarantine_checkpy).)
- **[1.0 release checklist](release-1.0-checklist.md)** & **[Product roadmap](roadmap.md)** — Exit criteria for 1.0 and prioritized engineering roadmap.
- **[Live experiment harness](guides/live-harness.md)** — Running controlled live experiment arms in disposable containers ([WIP-curve experiment](experiments/wip-curve-prereg.md): mutation-wave caps measured and kept · [Instruction-load ablation pre-registration](experiments/ablation-prereg.md): current activation load kept).
- **[Repository metadata](about.md)** — Canonical GitHub repository description and topics.

### Evidence & Historical Archives

- **[Retained run archive](runs/README.md)** — Every recorded mission execution, its SHA-256 inventory, and whether it binds to advance a mission's `metadata.proof` tier (`doctrine-only` → `self-run` → `external-run`).
- **[Decision log](DECISIONS.md)** & **[Changelog](../CHANGELOG.md)** — Durable gate decisions (mechanical, taste, and one-way auto-resolves, including floor waivers) and release history.
- **[Research archive](research/README.md)** — Dated ecosystem comparisons, positioning snapshots, and the ledger of rejected mission candidates.
- **[Historical reviews](reviews/)** & **[Completion records](completion/STATUS.md)** — Point-in-time repository audits (one dated file per review in `docs/reviews/`) and issue closure witnesses. Read historical records at their recorded date and SHA; always use [Install](install.md) and [Local development](development.md) for current commands.
