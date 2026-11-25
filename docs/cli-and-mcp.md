# Unified CLI, MCP Server & Mission Control UI

[Documentation Hub](README.md) · [Product Blueprint](product-blueprint.md) · [Install](install.md) · [Getting Started](getting-started.md)

The `open_fleet` package provides a single zero-dependency (Python 3.11+ stdlib) developer interface over the `open-fleet` catalog, verification kernel, and local SQLite runtime state.

---

## Install the CLI

From your clone of `open-fleet` (no third-party packages required):

```bash
# Editable install into your current Python environment:
pip install --no-build-isolation -e .

# Or invoke directly from the repository root without installing:
python3 -m open_fleet --help
```

---

## 60-Second Quickstart

```bash
# 1. Check local readiness (Python, git, runtime, harnesses, hooks, pins)
open-fleet doctor

# 2. See the independent verifier catch a gamed manifest live (zero LLM spend)
open-fleet demo --include-first-run

# 3. Route any engineering goal to the right outcome mission + launch prompt
open-fleet route "harden our API against auth bypass and SQL injection"

# 4. Link skills, atomically merge completion hooks, and register MCP for your host
open-fleet setup --host claude --wire-hooks --wire-mcp --dry-run

# 5. Launch the interactive Mission Control web cockpit
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
| `open-fleet status [--repo DIR] [--db PATH] [--json]` | Reads live SQLite `runtime.db` (`runs`, `tasks`, `dispatches`, `gates`, `merge_queue`), `.orca/events.jsonl`, `.orca/egress.jsonl`, and `docs/DECISIONS.md`. |
| `open-fleet certify [--provider NAME] [--json]` | Prints the honest certification matrix (`live-witnessed` vs `fixture-tested` vs `source-only` vs `unsupported`). |
| `open-fleet demo [--include-first-run] [--profile ro\|rw] [--json]` | Runs the negative-control head-to-head proof demo and optional standalone `posix` inert first-run witness. |
| `open-fleet preflight ...` / `open-fleet verify ...` / `open-fleet floor ...` | Clean pass-through wrappers over `preflight.py` (defaulting to `OPEN_FLEET_RUNTIME=auto`), `verify.py`, and `floor_guard.py`. |
| `open-fleet mcp [--repo DIR] [--print-config <host>]` | Starts the standards-compliant MCP JSON-RPC 2.0 stdio server, or prints the exact MCP registration config for your host. |
| `open-fleet ui [--host 127.0.0.1] [--port 8765] [--repo DIR]` | Starts **open-fleet Mission Control**, a local read-only + built-in-demo web dashboard over the catalog and live fleet state. |

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

- **12 Tools:** `fleet_doctor`, `fleet_route_mission`, `fleet_list_missions`, `fleet_get_mission`, `fleet_preflight`, `fleet_verify_manifest`, `fleet_floor_check`, `fleet_diff_scope`, `fleet_status`, `fleet_certification`, `fleet_decisions`, `fleet_run_demo`.
- **8 Resources:** `open-fleet://catalog/overview`, `open-fleet://catalog/missions`, `open-fleet://runtime/capabilities`, `open-fleet://runtime/certification`, `open-fleet://runtime/pins`, `open-fleet://runtime/quarantine`, `open-fleet://state/status`, `open-fleet://governance/decisions` (plus `open-fleet://catalog/mission/<name>`).
- **Prompts:** `mission/<name>` for every catalog mission with a structured `goal` argument.

---

## Mission Control UI (`open-fleet ui`)

Start locally with `open-fleet ui --port 8765` (binds to `127.0.0.1` by default for safety; pass `--host 0.0.0.0` only on trusted/proxied preview environments). It exposes five interactive tabs:

1. **Control Room:** Live KPIs, Environment Doctor diagnostics, Proof Ladder, SQLite fleet state, Retained Run Archive, and Durable Decisions log.
2. **Mission Router:** Natural-language goal router with quick presets, filterable catalog table, six-point identity inspector, and copy-ready prompts.
3. **Verification Lab:** 1-click live Negative-Control proof (`selfscore.py` GREEN vs `verify.py` RED), zero-spend standalone `posix` first-run witness (`ro`/`rw`), and interactive capability preflight tester.
4. **Runtime Matrix:** Live filterable certification table across all orchestrator providers and locally detected coding-agent harnesses.
5. **Setup & MCP Studio:** Host + runtime config generator with live dry-run setup plan and full MCP tool catalog.
