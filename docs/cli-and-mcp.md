# Unified CLI, MCP Server & Mission Control UI

[Documentation Hub](README.md) · [Product Blueprint](product-blueprint.md) · [Install](install.md) · [Getting Started](getting-started.md)

The `open_fleet` package provides a single zero-dependency (Python 3.11+ stdlib) developer interface over the `open-fleet` catalog, verification kernel, progressive mission state machines, solo-developer review lane, reusable PR GitHub Action, and local SQLite runtime state.

---

## Install the CLI

From your clone of `open-fleet` (no third-party packages required):

```bash
# Editable install into your current Python environment:
pip install --no-build-isolation -e .

# Or build and install a standalone wheel into any venv:
python3 -m pip wheel --no-build-isolation --no-deps . -w /tmp/of-dist

# Or invoke directly from the repository root without installing:
python3 -m open_fleet --help
```

When invoking the installed `open-fleet` / `open-fleet-mcp` binaries from outside the repository clone, set `OPEN_FLEET_ROOT=/path/to/open-fleet` (or pass `--root`).

---

## 60-Second Quickstart

```bash
# 1. Check local readiness (Python, git, runtime, harnesses, hooks, pins)
open-fleet doctor

# 2. See the independent verifier catch a gamed manifest live (zero LLM spend)
open-fleet demo --include-first-run

# 3. Route any engineering goal to the right outcome mission + launch prompt
open-fleet route "harden our API against auth bypass and SQL injection"

# 4. Run a progressive <5K-token/phase mission state machine with enforced gates
open-fleet session benchmark
open-fleet session start ship-it "Add GET /healthz with tests" --base fleet/healthz

# 5. Run the honest solo-developer review lane or drop-in PR CI gate locally
open-fleet solo-review --base origin/main
open-fleet ci-check --base origin/main

# 6. Link skills, atomically merge completion hooks, and register MCP for your host
open-fleet setup --host claude --wire-hooks --wire-mcp --dry-run

# 7. Launch the interactive Mission Control web cockpit
open-fleet ui --port 8765
```

---

## Unified CLI Commands

| Command | Purpose |
|---|---|
| `open-fleet doctor [--runtime auto\|posix\|orca] [--json]` | Diagnoses prerequisites, detected coding-agent harnesses, active runtime (`auto` recommendation), symlink/plugin stacking, completion-gate hooks, and quarantine status. |
| `open-fleet setup --host <host> [--wire-hooks] [--wire-mcp] [--dry-run] [--uninstall]` | Safely links missions for `claude`, `codex`, `gemini`, `opencode`, `antigravity`, or `cursor`; atomically merges `Stop`/`TaskCompleted` hooks without touching existing user settings; detects stacked plugin installs. |
| `open-fleet missions list [--proof ...] [--category ...] [--json]` | Lists all outcome missions with proof tier, token activation budget, and category. |
| `open-fleet missions show <name> [--json]` | Prints the mission's six-point identity contract, required capabilities, composed playbooks, and copy-ready launch prompt. |
| `open-fleet route "<goal>" [--top 5] [--json]` | Scores your goal against mission metadata and catalog synonyms to recommend the best-matching mission and prompt. |
| `open-fleet session {start,list,packet,approve,advance,benchmark}` | Runs progressive MCP-backed mission state machines (<5,000 tokens per phase, ~96% average token reduction), enforcing receipts, human one-way gate approvals (rejecting agent/bot self-approval), and `chain_check.py` terminal validation. |
| `open-fleet solo-review --base <ref> [--contract ...] [--manifest ...] [--lighting auto\|lit\|dark-eligible] [--nc-command ...]` | Honest solo-developer verified review lane: runs `diff_scope.py` + `floor_guard.py`, enforces the irreversibility stop-list (`AUTH`/`SECURITY`/`MIGRATIONS` remain strictly `lit`), emits a build-blind review packet for cross-model reviewers, and optionally invokes `verify.py` (never spoofing GitHub approvals). |
| `open-fleet ci-check --base <ref> [--manifest ...] [--workflow-snippet]` | Runs the composite PR verification gate (`floor_guard.py` + `diff_scope.py` + optional `verify.py`) locally or prints a drop-in GitHub Actions workflow using `.github/actions/open-fleet-verify`. |
| `open-fleet readiness [--check-cert] [--probes] [--json]` | Honest proof-graduation backlog (`doctrine-only` → bound `self-run`), locally actionable harness certification matrix, live `certification.py check`, and 5 pre-launch safety probes (`first_run.py probes`). |
| `open-fleet status [--repo DIR] [--db PATH] [--json]` | Reads live SQLite `runtime.db` (`runs`, `tasks`, `dispatches`, `gates`, `merge_queue`), `.orca/events.jsonl`, `.orca/egress.jsonl`, and `docs/DECISIONS.md`. |
| `open-fleet certify [--provider NAME] [--json]` | Prints the honest certification matrix (`live-witnessed` vs `fixture-tested` vs `source-only` vs `unsupported`). |
| `open-fleet demo [--include-first-run] [--profile ro\|rw] [--json]` | Runs the negative-control head-to-head proof demo and optional standalone `posix` inert first-run witness. |
| `open-fleet preflight ...` / `open-fleet verify ...` / `open-fleet floor ...` | Clean pass-through wrappers over `preflight.py` (defaulting to `OPEN_FLEET_RUNTIME=auto`), `verify.py`, and `floor_guard.py`. |
| `open-fleet mcp [--repo DIR] [--print-config <host>]` | Starts the standards-compliant MCP JSON-RPC 2.0 stdio server, or prints the exact MCP registration config for your host. |
| `open-fleet ui [--host 127.0.0.1] [--port 8765] [--repo DIR]` | Starts **open-fleet Mission Control**, a local web cockpit over the catalog, sessions, solo review, readiness workbench, and live fleet state. |

---

## Reusable GitHub Action (`.github/actions/open-fleet-verify`)

Add `open-fleet`'s quality-floor guard, scope-gated risk lens detection, and optional SHA-bound `verify.py` gate to any pull request workflow (generate the snippet with `open-fleet ci-check --workflow-snippet`):

```yaml
- name: Run open-fleet PR verification gate
  uses: ./.github/actions/open-fleet-verify
  with:
    base-ref: origin/${{ github.base_ref }}
    run-floor-guard: "true"
    run-diff-scope: "true"
```

All inputs are forwarded to `open_fleet/ci_action.py` strictly through `env:` (no shell interpolation of `${{ inputs.* }}` inside `run:`), and the action emits `$GITHUB_OUTPUT` keys (`overall-ok`, `floor-guard-status`, `diff-scope-status`, `verify-status`, `triggered-lenses`) plus a Markdown table in `$GITHUB_STEP_SUMMARY`.

---

## MCP Server (`open-fleet mcp`)

`open-fleet mcp` implements JSON-RPC 2.0 over `stdio` (supporting both newline-delimited JSON and `Content-Length` framing) with zero external dependencies. Print the ready-to-paste config for your agent host:

```bash
open-fleet mcp --print-config claude
open-fleet mcp --print-config codex
open-fleet mcp --print-config gemini
open-fleet mcp --print-config opencode
open-fleet mcp --print-config antigravity
open-fleet mcp --print-config cursor
```

### Exposed MCP Primitives

- **19 Tools:**
  - *Core & Verification:* `fleet_doctor`, `fleet_route_mission`, `fleet_list_missions`, `fleet_get_mission`, `fleet_preflight`, `fleet_verify_manifest`, `fleet_floor_check`, `fleet_diff_scope`, `fleet_status`, `fleet_certification`, `fleet_decisions`, `fleet_run_demo`.
  - *Progressive State Machines (<5K tok/phase):* `fleet_session_start`, `fleet_session_packet`, `fleet_session_approve_gate`, `fleet_session_advance`, `fleet_session_list`.
  - *Solo Review & Readiness:* `fleet_solo_review`, `fleet_readiness`.
- **10 Resources:** `open-fleet://catalog/overview`, `open-fleet://catalog/missions`, `open-fleet://runtime/capabilities`, `open-fleet://runtime/certification`, `open-fleet://runtime/pins`, `open-fleet://runtime/quarantine`, `open-fleet://state/status`, `open-fleet://governance/decisions`, `open-fleet://sessions/list`, `open-fleet://readiness/report` (plus `open-fleet://catalog/mission/<name>`).
- **Prompts:** `mission/<name>` for every catalog mission with a structured `goal` argument.

---

## Mission Control UI (`open-fleet ui`)

Start locally with `open-fleet ui --port 8765` (binds to `127.0.0.1` by default for safety; pass `--host 0.0.0.0` only on trusted/proxied preview environments). It exposes six interactive tabs:

1. **Control Room:** Live KPIs, Environment Doctor diagnostics, Proof Ladder, SQLite fleet state, Retained Run Archive, and Durable Decisions log.
2. **Mission Router:** Natural-language goal router with quick presets, filterable catalog table, six-point identity inspector, and copy-ready prompts.
3. **Sessions & Solo Review:** Live `<5K`-token progressive session stepper with one-way human gate approval controls, live solo-review `diff_scope` + `floor_guard` + build-blind packet generator, and copy-ready reusable PR GitHub Action workflow.
4. **Verification Lab:** 1-click live Negative-Control proof (`selfscore.py` GREEN vs `verify.py` RED), zero-spend standalone `posix` first-run witness (`ro`/`rw`), interactive capability preflight tester, 5 pre-launch negative safety probes (`first_run.py probes`), and live `floor_guard.py` check.
5. **Runtime & Readiness:** Live certification matrix across all orchestrator providers and locally detected coding-agent harnesses, 1-click `certification.py check`, and the honest Proof-Graduation Workbench.
6. **Setup & MCP Studio:** Host + runtime config generator with live dry-run setup plan and full 19-tool MCP catalog.

---

## Implementation Anchors

Every core product subsystem in `open_fleet` is bound below to its live Python `file:symbol` implementation anchor and AST-verified by `python3 -I scripts/extract_product_surface.py --check` (renaming any anchored symbol turns the claim check RED):

| Subsystem | Live `file:symbol` Anchors |
|---|---|
| Unified CLI & dispatch | `open_fleet/cli.py:build_parser`, `open_fleet/cli.py:main` |
| Catalog & goal routing | `open_fleet/catalog.py:catalog_overview`, `open_fleet/catalog.py:route_intent` |
| Local SQLite state & telemetry | `open_fleet/state.py:read_workspace_status`, `open_fleet/state.py:read_runtime_state` |
| Zero-dep MCP JSON-RPC 2.0 server | `open_fleet/mcp_server.py:OpenFleetMCPServer`, `open_fleet/mcp_server.py:serve_stdio` |
| Progressive `<5K`-token mission sessions | `open_fleet/sessions.py:start_session`, `open_fleet/sessions.py:approve_gate`, `open_fleet/sessions.py:advance_session`, `open_fleet/sessions.py:benchmark_progressive_savings` |
| Honest solo-developer review lane | `open_fleet/solo_review.py:run_solo_review` |
| Reusable PR GitHub Action runner | `open_fleet/ci_action.py:run_ci_verify` |
| Proof-graduation readiness workbench | `open_fleet/readiness.py:readiness_report` |
| Environment doctor & atomic host setup | `open_fleet/setup.py:doctor`, `open_fleet/setup.py:setup_host` |
| Mission Control HTTP UI server | `open_fleet/ui_server.py:MissionControlApp` |
