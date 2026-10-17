# Re-pin delta inventory — 1.4.224 pin → 1.4.229 candidate (2026-10-17)

Status: CLOSED 2026-10-17 — PINNED-WITH-PARKED at v1.4.229 (`a0cd1644f320f1327f7495650a816111b495f3cd`).

## Scope & source

- Previous pin: `v1.4.224` (`2bb20586ebc39d605e16d95f57420e20a16e7485`, witnessed 2026-10-13).
- Target pin: `v1.4.229` (`a0cd1644f320f1327f7495650a816111b495f3cd`, released 2026-10-17; upstream `main` at `38131048b1`).
- Diffed surfaces: `skills/`, `skill-guides/`, `src/cli/specs/`, `src/shared/orchestration-*`, `src/shared/tui-agent-*`, `src/main/runtime/orchestration/db/contract-constants.ts`.

## Per-item classification

| ID | Upstream change (v1.4.224 → v1.4.229) | Fleet surface affected | Source citation | Disposition |
|---|---|---|---|---|
| D229-1 | Added `orca jira` command group (19 subcommands: `connection`, `issue`, `list`, `search`, `create`, `project list/types/fields`, `comment list/add`, `status list/set`, `assignee list/set/clear`, `priority list/set/clear`, `label add/rm/set`) and `orca-jira` + `jira-tickets` skills | `playbooks/linear-enumeration.md` (§ "Jira is a drawer, not a denominator source" claimed no Jira CLI existed) | `src/cli/specs/jira.ts`, `skill-guides/orca-jira.md`, `skill-guides/jira-tickets.md`, `skills/orca-jira/SKILL.md`, `skills/jira-tickets/SKILL.md` | **PATCHED** (`playbooks/linear-enumeration.md` updated with `orca jira` JQL denominator, `--site <id>`, transition-based `status set`, and single-attempt write verification) |
| D229-2 | Added `orca agent launch` (`--agent`, `--worktree`, `--prompt`, `--model`, `--effort`, `--focus`, `--retry-launch`) and extended `orca worktree create --agent` with `--model`, `--effort`, `--retry-launch`, `--reference`, `--reference-site` | `runtime/dispatch-lifecycle.md`, `runtime/orca-pin.md` | `src/cli/specs/agent-launch.ts`, `src/cli/specs/core.ts:119-160`, `skill-guides/orca-cli.md:39-103`, `skill-guides/orchestration.md:107-113` | **PATCHED** (documented in `runtime/dispatch-lifecycle.md` and `runtime/orca-pin.md`; supervised units stay on `worker-start`) |
| D229-3 | Added `orca reference list|add|remove|find` for attaching/detaching/searching PRs, Linear issues, GitLab MRs/issues, and Jira issues across workspaces and finding active agents (`linked`, `liveness`, `terminal`, `mailbox`) | `runtime/dispatch-lifecycle.md`, `playbooks/linear-enumeration.md` | `src/cli/specs/reference.ts`, `skill-guides/orca-cli.md:105-123` | **PATCHED** (documented in `runtime/dispatch-lifecycle.md` and `playbooks/linear-enumeration.md`) |
| D229-4 | Added `orca serve --supervise`, `orca serve restore resume`, `orca serve service install|status|uninstall`, `orca terminal-daemon status|restart --yes`, and OS terminal containment env vars `ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX`, `ORCA_TERMINAL_MEMORY_SWAP_MAX` | `runtime/sandbox-policy.md`, `runtime/threat-model.md` | `src/cli/specs/serve.ts`, `src/cli/specs/terminal-daemon.ts`, `skill-guides/orca-cli.md:166-225`, `skill-guides/orca-per-workspace-env.md:92-120` | **PATCHED** (documented in `runtime/sandbox-policy.md` and `runtime/threat-model.md` Boundary 1) |
| D229-5 | `task_not_startable` refusal (`TaskNotStartableDetail`) adds `failureCount?: number` on 3-failure circuit breaker; failed `worker-start` attempts count across `--retry-of` (worker's own `failed` report does not); `--retry-of` replacement of a `failed` worker releases the terminal it owned | `runtime/dispatch-lifecycle.md`, `runtime/orca-dag-semantics.md` | `src/shared/orchestration-dispatch-refusal-contract.ts:14-19`, `skill-guides/orchestration/references/recovery-and-cleanup.md:130-167` | **PATCHED** (documented in `runtime/dispatch-lifecycle.md` and `runtime/orca-dag-semantics.md`) |
| D229-6 | `orca automations runs` adds `--limit <n>` and `--cursor <cursor>` paging; finished automation runs sleep their terminal instead of closing it | `runtime/mission-scheduling.md` | `src/cli/specs/automations.ts:114-130`, `skill-guides/orca-cli.md:155-162` | **PATCHED** (documented in `runtime/mission-scheduling.md`) |
| D229-7 | `ORCA_CHAT_VISUALS_DIR` renamed to `ORCA_CHAT_SCRATCH_DIR` (30-day retention); `orca skills install/update` pins `<repo>/tree/<commit>` to build commit and accepts `--agent`; `SCHEMA_VERSION` stays `43` | None (no fleet script or policy references `ORCA_CHAT_VISUALS_DIR`; `orca-dag-semantics.md` schema line updated to cite v43 at v1.4.229) | `resources/native-chat-visuals/skills/orca-chat-visuals/SKILL.md`, `src/cli/specs/skills.ts`, `src/main/runtime/orchestration/db/contract-constants.ts:23` | **NOTED / CURRENT** |

## Complete `runtime/*.md` policy drift table (16 / 16 files)

| Policy file | Upstream Orca surface | v1.4.229 verdict | Notes |
|---|---|---|---|
| `runtime/attention-budget.md` | `gate-list`, `gate-approve`, `gate-reject`, `gate-expire`, `gate-ask` (`src/cli/specs/orchestration.ts:535-611`) | **PATCHED** | Line-number citation updated (`500-576` → `535-611`). |
| `runtime/conductor-close.md` | `worker-list`, `worker-release`, `terminal close`, `terminal stop`, `worktree rm` | **CURRENT** | All closeout verbs, exit codes, and `--force-dirty` semantics unchanged at v1.4.229. |
| `runtime/dispatch-lifecycle.md` | `worktree create`, `worker-start`, `agent launch`, `reference`, `task_not_startable` | **PATCHED** | Added `orca agent launch`, `orca reference list\|add\|remove\|find`, `worktree create --agent` flags (`--model`, `--effort`, `--retry-launch`, `--reference`, `--reference-site`), and `task_not_startable.failureCount`. |
| `runtime/evidence-manifest.md` | SHA-bound manifest schema, `verify.py` / `verify-gate.sh` contract | **CURRENT** | Fleet-owned verification contract; no upstream drift. |
| `runtime/gate-classification.md` | `gate-ask`, `gate-approve`, `gate-reject`, `gate-expire`, `runtime/one-way-doors.json` (`src/cli/specs/orchestration.ts:535-611`) | **PATCHED** | Line-number citation updated (`500-576` → `535-611`); gate verbs unchanged. |
| `runtime/ledger-contract.md` | `orca orchestration` SQLite ledger, `ledger_runs`, `ledger_tasks`, `ledger_workers` | **CURRENT** | Schema v43 (`contract-constants.ts:23`) unchanged since v1.4.224. |
| `runtime/liveness-resume.md` | `terminal list/read/wait`, `worker-list`, `worker-start --retry-of`, `watchdog.py` | **CURRENT** | Heartbeat, nudge, and `--retry-of` semantics unchanged at v1.4.229. |
| `runtime/merge-serialization.md` | `git merge-base --is-ancestor`, serialized conductor merge queue | **CURRENT** | Fleet-owned merge serialization policy; no upstream drift. |
| `runtime/mission-chaining.md` | `chain_check.py`, sequential mission handoff contract | **CURRENT** | Fleet-owned chaining contract; no upstream drift. |
| `runtime/mission-scheduling.md` | `orca automations create\|list\|get\|update\|delete\|run\|runs\|approve\|reject` (`src/cli/specs/automations.ts:1-151`) | **PATCHED** | Added `orca automations runs --limit <n> --cursor <cursor>` and sleeping finished automation terminals (`D229-6`). |
| `runtime/orca-dag-semantics.md` | `task-create`, `task-update`, `task-dep-*`, `worker-start`, `task_not_startable.failureCount` | **PATCHED** | Added `task_not_startable.failureCount` and automatic terminal release when `--retry-of` replaces a `failed` worker (`D229-5`). |
| `runtime/orca-pin.md` | Upstream pin witness record (`v1.4.229`, `a0cd1644f320f1327f7495650a816111b495f3cd`) | **PATCHED** | Advanced to `v1.4.229` (witnessed 2026-10-17; next scheduled review `2026-12-28`). |
| `runtime/reviewed-sha-freshness.md` | `reviewed_sha == head_sha` / tree-hash equivalence | **CURRENT** | Fleet-owned review freshness rule; no upstream drift. |
| `runtime/sandbox-policy.md` | `ro`/`rw`/`danger` profiles, `ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX`, `ORCA_TERMINAL_MEMORY_SWAP_MAX` | **PATCHED** | Added v1.4.229 OS process/memory containment env vars (`D229-4`). |
| `runtime/threat-model.md` | Four boundaries (`Sandbox`, `Network`, `Supply chain`, `Identity & access`) + five-step response ladder | **PATCHED** | Added v1.4.229 OS process/memory ceiling under Boundary 1 (`D229-4`). |
| `runtime/worker-supervision.md` | `orca orchestration check/send/reply`, `worker_done`, `gate_request`, `progress`, `blocker` | **CURRENT** | Envelope types and supervision loop unchanged at v1.4.229. |

## Complete `runtime/scripts/` entry-point drift table (37 / 37 files)

| Script entry point | Role / upstream dependency | v1.4.229 verdict |
|---|---|---|
| `runtime/scripts/_verify_sig.py` | Shared Ed25519 signature verification helper for `verify.py` | **CURRENT** |
| `runtime/scripts/chain_check.py` | Sequential mission chain precondition checker | **CURRENT** |
| `runtime/scripts/check_reply.py` | Wrapper around `orca orchestration check` / `reply` (`--caller-terminal`, `--mark-read`) | **CURRENT** |
| `runtime/scripts/decisions.py` | Append-only mechanical/taste/one-way decision log helper | **CURRENT** |
| `runtime/scripts/deny-hook.sh` | `PreToolUse` bash/file sandbox & receipted-egress enforcement hook | **CURRENT** |
| `runtime/scripts/diff_scope.py` | Diff scope classifier (`code`, `docs`, `tests`, `config`) | **CURRENT** |
| `runtime/scripts/diffparse.py` | Unified diff parser for `verify.py` and `diff_scope.py` | **CURRENT** |
| `runtime/scripts/dispatch-sign.py` | Ed25519 task-contract signer (`key-gen`, `sign`, `verify`) | **CURRENT** |
| `runtime/scripts/ed25519.py` | Pure-Python RFC 8032 Ed25519 implementation | **CURRENT** |
| `runtime/scripts/egress.py` | Hash-chained outbound GitHub write wrapper (`gh pr/issue/release/api`) | **CURRENT** |
| `runtime/scripts/evidence-run.py` | Automated test + negative-control runner emitting manifest fields | **CURRENT** |
| `runtime/scripts/floor_guard.py` | Monotonic ratchet enforcement (`floor-it`) | **CURRENT** |
| `runtime/scripts/gate-batch.py` | Batch classifier and presenter for pending `gate_request` envelopes | **CURRENT** |
| `runtime/scripts/gitexec.py` | Timeout-bounded `git` subprocess helper | **CURRENT** |
| `runtime/scripts/guard_text.py` | Untrusted text trust-envelope fence (`issue`, `pr`, `ci`, `web`) | **CURRENT** |
| `runtime/scripts/hitl-loop.template.sh` | Bounded human-in-the-loop reproduction script template | **CURRENT** |
| `runtime/scripts/hitl_ask.py` | Durable file-backed HITL prompt/resume helper | **CURRENT** |
| `runtime/scripts/inventory.py` | Deterministic `sha256` directory inventory generator/checker | **CURRENT** |
| `runtime/scripts/orca_cli.py` | Shared Orca CLI invocation & JSON envelope parser | **CURRENT** |
| `runtime/scripts/pin_review.py` | Upstream skill-pack pin & rug-pull scanner against `runtime/pins.json` | **CURRENT** |
| `runtime/scripts/pm.py` | Package-manager detector (`npm`, `pnpm`, `yarn`, `bun`, `pytest`, `cargo`, `go`) | **CURRENT** |
| `runtime/scripts/preflight.py` | Pre-mission environment, Orca CLI, and quarantine preflight gate | **CURRENT** |
| `runtime/scripts/proof_status.py` | Catalog proof-tier summary & ratchet auditor | **CURRENT** |
| `runtime/scripts/quarantine_check.py` | Fail-closed `runtime/quarantine.json` deny-list enforcer (`#558`) | **CURRENT** |
| `runtime/scripts/run_report.py` | Binding validator for `docs/runs/<run>.md` headers, manifests, and sha256 inventories | **CURRENT** |
| `runtime/scripts/sandbox_doctor.py` | Host sandbox & worktree isolation readiness check | **CURRENT** |
| `runtime/scripts/search_sessions.py` | Prior session transcript search helper | **CURRENT** |
| `runtime/scripts/send_msg.py` | Wrapper around `orca orchestration send` (`--from`, `--to`, `--type`, `--content`) | **CURRENT** |
| `runtime/scripts/spawn_worker.sh` | Worktree creation + `worker-start` dispatcher with profile flags | **CURRENT** |
| `runtime/scripts/task_ops.py` | Wrapper around `orca orchestration task-create/update/list/get/dep-*` | **CURRENT** |
| `runtime/scripts/terminal_ops.py` | Wrapper around `orca terminal list/read/send/wait/stop/close` | **CURRENT** |
| `runtime/scripts/upstream_probe.py` | Live probe harness for verifying Orca CLI contracts on a target binary | **CURRENT** |
| `runtime/scripts/verify-gate.sh` | Coordinator shell wrapper invoking `verify.py` | **CURRENT** |
| `runtime/scripts/verify.py` | Independent SHA-bound evidence manifest verifier | **CURRENT** |
| `runtime/scripts/watchdog.py` | Liveness monitor classifying workers (`ALIVE`, `IDLE`, `STUCK`, `DEAD`, `LOOPING`) | **CURRENT** |
| `runtime/scripts/worker_ops.py` | Wrapper around `orca orchestration worker-start/list/get/release` | **CURRENT** |
| `runtime/scripts/worktree_ops.py` | Wrapper around `orca worktree list/create/rm` | **CURRENT** |
| `runtime/scripts/wtree.sh` | Shell worktree helper for standalone local runs | **CURRENT** |

