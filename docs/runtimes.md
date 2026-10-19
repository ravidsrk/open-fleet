# Multi-runtime & harness guide (`open-fleet` RPI)

[Documentation](README.md) · [Runtime scripts](runtime-scripts.md) · [Verify gate](verify-gate.md) · [Architecture](../ARCHITECTURE.md)

`open-fleet` decouples mission outcomes, phase playbooks, and verification gates from any single orchestrator binary through the **Runtime Provider Interface (RPI)**. Every general mission runs unchanged across 14 orchestrator providers and dispatches workers across 10+ coding-agent harnesses under uniform least-privilege sandbox profiles (`ro`, `rw`, `danger`).

---

## Selecting a runtime provider

Set `OPEN_FLEET_RUNTIME` (or the legacy alias `ORCA_FLEET_RUNTIME`) to select the active orchestrator provider:

```bash
export OPEN_FLEET_RUNTIME=posix      # zero-dependency SQLite WAL + git worktree + tmux/nohup
export OPEN_FLEET_RUNTIME=overstory  # jayminwest/overstory adapter
export OPEN_FLEET_RUNTIME=t3code     # pingdotgg/t3code WebSocket event-sourced adapter
export OPEN_FLEET_RUNTIME=ao         # ComposioHQ/agent-orchestrator adapter
export OPEN_FLEET_RUNTIME=superset   # superset-sh/superset worktree adapter
export OPEN_FLEET_RUNTIME=orca       # stablyai/orca native binary
```

When `OPEN_FLEET_RUNTIME` is unset or set to `auto`, [`runtime/scripts/orca_cli.py`](../runtime/scripts/orca_cli.py) probes the environment and selects `orca` when a responsive Orca binary is on `PATH`, or falls back to the portable `posix` provider.

### Neutral environment variables

Every runtime helper honors `OPEN_FLEET_*` primary environment variables while preserving backward compatibility with `ORCA_*`:

| Primary (`open-fleet`) | Legacy fallback (`orca-fleet`) | Purpose |
|---|---|---|
| `OPEN_FLEET_RUNTIME` | `ORCA_FLEET_RUNTIME` | Active RPI orchestrator provider (`orca`, `posix`, `overstory`, `t3code`, `ao`, `superset`, `gastown`, `worktrunk`, `jcode-swarm`, `emdash`, `vibe-kanban`, `paperclip`, `multiclaude`, `openhands`, or `auto`) |
| `OPEN_FLEET_ROOT` | `ORCA_FLEET_ROOT` | Fleet catalog root directory |
| `OPEN_FLEET_SANDBOX_PROFILE` | `ORCA_SANDBOX_PROFILE` | Worker sandbox profile (`ro`, `rw`, `danger`) |
| `OPEN_FLEET_PARENT_PROFILE` | `ORCA_PARENT_PROFILE` | Parent worker's sandbox profile for monotonic narrowing (`ro < rw < danger`) |
| `OPEN_FLEET_UNIT_WORKTREE` | `ORCA_UNIT_WORKTREE` | Active worker worktree boundary enforced by `deny-hook.sh` |
| `OPEN_FLEET_GATE_MANIFEST` / `OPEN_FLEET_MANIFEST` | `ORCA_MANIFEST` | Evidence manifest path verified by `verify-gate.sh` |
| `OPEN_FLEET_UNIT_CLASS` | `ORCA_UNIT_CLASS` | Unit class (`mutation`, `report-only`, `planning`) for `verify-gate.sh` |
| `OPEN_FLEET_EGRESS_LEDGER` | `ORCA_EGRESS_LEDGER` | Hash-chained off-repo egress receipt ledger path (`egress.py`) |
| `OPEN_FLEET_DECISIONS_FILE` | `ORCA_DECISIONS_FILE` | Decisions log path (`decisions.py`) |

---

## Capability matrix and preflight enforcement

[`runtime/providers/capabilities.json`](../runtime/providers/capabilities.json) declares the 8 runtime capabilities, each provider's native and portable fallback capabilities, and each mission's required and optional capabilities:

| Capability ID | Description | Portable fallback |
|---|---|---|
| `cap:core-orchestration` | Worktree lifecycle, run/task state, worker spawn/fence, and two-way mailbox messaging | `runtime/providers/local_state.py` (SQLite WAL + `git worktree` + `tmux`/`nohup`) |
| `cap:sandbox-vm` | Disposable VM or container isolation for untrusted execution and recipe checks | [`runtime/scripts/sandbox_doctor.py`](../runtime/scripts/sandbox_doctor.py) (Docker, Podman, `bwrap`, Gondolin, E2B, Daytona, Modal, Fly, Sprites) |
| `cap:session-search` | Cross-session FTS5 transcript search for prior-art recall | [`runtime/scripts/search_sessions.py`](../runtime/scripts/search_sessions.py) |
| `cap:browser` | Headless browser DOM snapshot, console/network capture, and CWV/a11y probing | Playwright CLI / Chrome DevTools MCP |
| `cap:mobile-emulator` | iOS Simulator and Android Emulator lifecycle, screenshot, and UI hierarchy dump | `xcrun simctl` (macOS) and Android `adb` |
| `cap:issue-tracker` | Issue and pull-request enumeration, creation, commenting, and state transitions | GitHub CLI (`gh`) and `runtime/scripts/pm.py` |
| `cap:scheduler` | Recurring cron/interval execution for unattended sweeps | POSIX `crontab` / `systemd-run` / GitHub Actions `schedule` |
| `cap:orca-self-audit` | Live inspection of the proprietary `stablyai/orca` binary and `orca skills get` bundle | None — exclusive to `orca` (required only by [`skills/pin-it/SKILL.md`](../skills/pin-it/SKILL.md)) |

### Running capability preflight

[`runtime/scripts/preflight.py`](../runtime/scripts/preflight.py) checks mission capability requirements against the selected runtime provider and fails closed (exit `2`) when a required capability is unavailable:

```bash
# General missions pass on posix and all other RPI providers:
python3 runtime/scripts/preflight.py --mission ship-it --runtime posix --mode readonly

# pin-it requires cap:orca-self-audit and fails closed on non-orca runtimes:
python3 runtime/scripts/preflight.py --mission pin-it --runtime posix --mode readonly
# -> exit 2: preflight: ERROR: mission 'pin-it' cannot run on runtime 'posix' — missing_capability: cap:orca-self-audit

# Require native provider capabilities without portable fallbacks:
python3 runtime/scripts/preflight.py --mission offload-it --runtime posix --strict-native-capabilities --mode readonly
```

---

## Supported orchestrator providers (14)

All 14 providers implement [`RuntimeProvider`](../runtime/providers/base.py) and return Orca-compatible JSON envelopes so existing coordinator scripts (`task_ops.py`, `worker_ops.py`, `worktree_ops.py`, `terminal_ops.py`, `send_msg.py`, `check_reply.py`, `hitl_ask.py`, `watchdog.py`) work without modification.

### Tier 1 — Primary providers

| Provider | Upstream | Architecture | Native capabilities |
|---|---|---|---|
| `orca` | `stablyai/orca` | Native desktop/CLI control plane | All 8 capabilities including `cap:orca-self-audit` |
| `posix` | `open-fleet/posix` | Zero-dependency SQLite WAL (`~/.open-fleet/state.db`) + `git worktree` + `tmux`/daemon | `cap:core-orchestration`, `cap:session-search`, `cap:issue-tracker`, `cap:scheduler` |
| `overstory` | `jayminwest/overstory` | `ov` CLI + `.overstory/mail.db` SQLite mailbox + `ov worktree` | `cap:core-orchestration`, `cap:session-search`, `cap:issue-tracker` |
| `t3code` | `pingdotgg/t3code` | Event-sourced WebSocket RPC (`ws://127.0.0.1:3773`) + terminal API | `cap:core-orchestration`, `cap:browser`, `cap:issue-tracker` |
| `ao` | `ComposioHQ/agent-orchestrator` | `ao spawn` / `ao send` / `ao status` + YAML session metadata | `cap:core-orchestration`, `cap:issue-tracker`, `cap:scheduler` |
| `superset` | `superset-sh/superset` | Worktree-first terminal IDE + background agent sessions | `cap:core-orchestration`, `cap:session-search`, `cap:issue-tracker` |

### Tier 2 — Ecosystem adapters

| Provider | Upstream | Architecture | Native capabilities |
|---|---|---|---|
| `gastown` | `steveyegge/gastown` | Go `gt` workspace + `bd` beads graph ledger (`gt sling`, `gt mail`, `gt nudge`) | `cap:core-orchestration`, `cap:issue-tracker`, `cap:scheduler` |
| `worktrunk` | `max-sixty/worktrunk` | Rust `wt` worktree lifecycle (`wt list --format=json`, `wt switch --create`) + SQLite state | `cap:core-orchestration` |
| `jcode-swarm` | `1jehuang/jcode` | Rust unix-socket swarm coordinator + native session/transcript search | `cap:core-orchestration`, `cap:session-search` |
| `emdash` | `generalaction/emdash` | PTY ring buffer + worktree lifecycle + container/SSH task runner | `cap:core-orchestration`, `cap:sandbox-vm`, `cap:issue-tracker` |
| `vibe-kanban` | `BloopAI/vibe-kanban` | Rust Axum + SQLite kanban server (`/api/task-attempts`) | `cap:core-orchestration`, `cap:sandbox-vm`, `cap:browser`, `cap:issue-tracker` |
| `paperclip` | `paperclipai/paperclip` | Control-plane REST API (`/api/companies/:id/issues`, atomic checkout, heartbeats) | `cap:core-orchestration`, `cap:issue-tracker`, `cap:scheduler` |
| `multiclaude` | `dlorenc/multiclaude` | Go `tmux` + `git worktree` daemon (`multiclaude work`, `message send/list/ack`) | `cap:core-orchestration`, `cap:issue-tracker` |
| `openhands` | `OpenHands/OpenHands` | Container/Kubernetes sandboxed agent runtime (`/api/conversations`) | `cap:core-orchestration`, `cap:sandbox-vm`, `cap:browser`, `cap:issue-tracker` |

---

## Supported coding-agent harnesses & sandbox profiles

[`runtime/providers/base.py`](../runtime/providers/base.py) (`build_harness_command`) and [`runtime/sandbox-policy.md`](../runtime/sandbox-policy.md) enforce three least-privilege worker profiles with **monotonic privilege narrowing** (`ro < rw < danger` — a parent running under `ro` can never spawn a `rw` or `danger` child):

- **`ro` (read-only)**: reviewers, research workers, root-cause investigators, and spec auditors. All file mutation and arbitrary shell execution tools are disabled at the CLI flag/config level and guarded by `deny-hook.sh`.
- **`rw` (worktree-scoped read-write)**: slice builders, bug fixers, and test authors. Mutations outside `OPEN_FLEET_UNIT_WORKTREE` / `ORCA_UNIT_WORKTREE` and destructive git/GitHub commands are blocked by `deny-hook.sh`.
- **`danger` (disposable sandbox)**: exploit PoCs and full-container operations inside an isolated VM/container (`cap:sandbox-vm`).

| Harness | Binary | `PROFILE=ro` enforcement | `PROFILE=rw` / `danger` enforcement |
|---|---|---|---|
| Claude Code | `claude` | `claude -p --permission-mode plan --disallowedTools Edit,Write,MultiEdit,NotebookEdit` | `claude -p --dangerously-skip-permissions` + `PreToolUse` `deny-hook.sh` |
| OpenAI Codex | `codex` | `codex exec --json -C <wt> --sandbox read-only -c 'approval_policy="never"'` | `codex exec --json -C <wt> --dangerously-bypass-approvals-and-sandbox` + `deny-hook.sh` |
| OpenCode | `opencode` | `OPENCODE_CONFIG_CONTENT='{"permission":{"*":"allow","edit":"deny","bash":"deny","external_directory":"deny"}}' opencode run --standalone` | `opencode run --auto --standalone --format json --dir <wt>` + plugin bridge |
| Oh My Pi (`omp`) | `omp` | `omp -p --mode json --cwd <wt> --no-session --no-lsp --tools read,grep,glob,find,ast_grep --approval-mode always-ask` | `omp -p --mode json --cwd <wt> --yolo --trusted-extension omp_pi_deny_bridge.ts` |
| Pi (`pi-mono`) | `pi` | `cd <wt> && pi -p --mode json --no-session --no-mcp -ne -na --tools read,grep,find,ls --exclude-tools 'bash,powershell,write,edit,codemode,mcp__*'` | `cd <wt> && pi -p --mode json -e omp_pi_deny_bridge.ts --tools read,bash,edit,write,grep,find,ls` |
| `jcode` | `jcode` | `jcode -C <wt> --no-update -q --tools read,agentgrep,ls,session_search,conversation_search,memory,web_search --disabled-tools bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp run` | `JCODE_HOOK_PRE_TOOL=deny-hook.sh jcode -C <wt> --no-update -q --disabled-tools selfdev,desktop_selfdev run` |
| Goose | `goose` | `GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin analyze` | `GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin developer` |
| Hermes Agent | `hermes` | `HERMES_WRITE_SAFE_ROOT=/dev/null hermes --in <wt> --accept-hooks chat --oneshot -Q --toolsets file,web,session_search` | `HERMES_WRITE_SAFE_ROOT=<wt> hermes --in <wt> --yolo --accept-hooks chat --oneshot -Q --toolsets coding` |
| Crush | `crush` | `crush --cwd <wt> --data-dir <wt>/.crush-orca-ro run -q` (`disabled_tools: ["bash","write","edit","multiedit"]`) | `crush --cwd <wt> --data-dir <wt>/.crush --yolo run -q` |
| Gemini CLI | `gemini` | `gemini --approval-mode plan` | `gemini --yolo` + `BeforeTool` `deny-hook.sh` |
| Cursor / Antigravity / Grok / Droid | `cursor` / `agy` / `grok` / `droid` | Refused on `PROFILE=ro` (`unsupported_profile`: no verified read-only CLI flag) | `--yolo` / `--dangerously-skip-permissions` / `--permission-mode bypassPermissions` / `--auto high` |
