# Multi-Runtime & Harness Guide (`open-fleet` RPI)

[Documentation Hub](README.md) · [Certification Matrix](certification.md) · [Runtime Scripts](runtime-scripts.md) · [Verify Gate](verify-gate.md)

`open-fleet` decouples mission outcomes, phase playbooks, and verification gates from any single orchestrator binary through the **Runtime Provider Interface (RPI)**. Every general mission runs across **14 orchestrator providers** (two need more than core orchestration: `offload-it` requires `cap:sandbox-vm`, native on `orca` and a Docker-probed fallback on `posix`, so the other 12 providers refuse it; `field-test-it` needs `adb` or `xcrun` on `PATH` off `orca`) and dispatches workers across **14 CLI coding-agent harnesses** (10 with verified headless `ro` and `rw` launches; `cursor`, `antigravity`, `grok`, and `droid` `rw`-only where a provider launches them) plus the `openhands` SDK agent, under uniform least-privilege sandbox profiles (`ro`, `rw`, `danger`).

> [!IMPORTANT]
> **Advertised vs. Certified:** Every provider, profile, and harness listed below has an explicit certification status in **[Provider & harness certification](certification.md)** (`live-witnessed`, `fixture-tested`, `source-only`, `unsupported`, or `unavailable`, plus a computed `stale` when a pin moves). Today, Claude Code is live-witnessed on both the `orca` route (`ro`, `rw`) and the standalone `posix` route (`ro`, `rw`, bound [2026-10-24](runs/2026-10-24-review-it-first-run.md)).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/diagrams/runtime-providers.jpg">
    <source media="(prefers-color-scheme: light)" srcset="assets/diagrams/runtime-providers-light.jpg">
    <img src="assets/diagrams/runtime-providers-light.jpg" alt="How the mission catalog runs across 14 orchestrator runtimes and 15 coding-agent harnesses: missions and playbooks call neutral runtime/scripts entrypoints; OPEN_FLEET_RUNTIME selects orca (the default), posix (standalone SQLite WAL and local git worktrees) or one of 12 external orchestrators, while each worker's agent argument to spawn_worker.sh selects its coding agent (cursor, antigravity, grok and droid rw only) and PROFILE maps it to ro, rw or danger; both feed the same independent SHA-bound verifier (verify.py, verify-gate.sh and run_report.py)" width="820">
  </picture>
</p>

## Selecting a runtime provider

Set `OPEN_FLEET_RUNTIME` (or the legacy alias `ORCA_FLEET_RUNTIME`) to choose how fleets manage worktrees, worker processes, and task state:

```bash
export OPEN_FLEET_RUNTIME=orca       # Default: stablyai/orca native desktop/CLI control plane
export OPEN_FLEET_RUNTIME=posix      # Standalone: SQLite WAL + git worktree + tmux / cmux / setsid (no Orca app needed)
export OPEN_FLEET_RUNTIME=auto       # Uses 'orca' if the binary is on PATH, otherwise falls back to 'posix'
export OPEN_FLEET_RUNTIME=overstory  # jayminwest/overstory `ov` CLI adapter
export OPEN_FLEET_RUNTIME=t3code     # pingdotgg/t3code MCP thread tools via `t3 acp-mcp-call`
export OPEN_FLEET_RUNTIME=ao         # ComposioHQ/agent-orchestrator loopback HTTP daemon
export OPEN_FLEET_RUNTIME=superset   # superset-sh/superset CLI adapter
```

### How standalone `posix` mode works

- **Zero-daemon SQLite state store:** Defaults to `~/.open-fleet/state/<repo-id>/runtime.db` (keyed by the repository's git common dir so linked worktrees share one store; override via `OPEN_FLEET_STATE_DB` or `OPEN_FLEET_STATE_DIR`). Concurrent openers safely contend for WAL initialization and run schema migrations inside `BEGIN IMMEDIATE` transactions.
- **What a worker inherits:** the coordinator's environment, minus the fleet-custody secrets in `WORKER_ENV_DENYLIST` (the dispatch signing seeds, `ORCA_CLOUD_AUTH_TOKEN`, the Paperclip and OpenHands API keys) and anything named in `OPEN_FLEET_WORKER_ENV_DENY` (comma- or space-separated names or globs, e.g. `GH_TOKEN,AWS_*`). The strip applies to the spawn, to a `tmux`/`cmux` server the spawn starts, and in the monitor to the environment an already-running server hands it. Harness credentials and proxy settings pass through because no allowlist of them is known; [`runtime/threat-model.md`](../runtime/threat-model.md) names ambient credentials as the residual risk. The state directory, each lane (`run_worker.py`, `worker_env.json`, `events.jsonl`) and the database are created user-private (`0700`/`0600`); a directory the operator already had keeps its mode.
- **A monitor killed on its own:** the monitor leads the process group its agent runs in. When only the monitor dies, the liveness sweep (`worker-list`) and `worker_fence stop` end the group it left — but only when a live member's working directory (read from `/proc`, so Linux hosts) is that dispatch's worktree or lane, so a group id the kernel has since handed to someone else is never signalled — and record `orphaned_worker_stopped` in the lane's `events.jsonl` before the `worker_died`. A live pid that no longer runs that lane's `run_worker.py` counts as a vanished monitor, not a live one.
- **Completion signaling for `ro` vs. `rw` workers:** `rw` workers report completion via `send_msg.py --type worker_done`. Because `PROFILE=ro` workers either strip shell/write tools or run under plan mode + the `OPEN_FLEET_HOOK_READONLY=1` write floor without mutating state, `worker_start` appends a completion marker instruction (`OPEN_FLEET_WORKER_DONE <dispatch-id> <succeeded|failed>`) on monitored backends (`setsid`, `tmux`, `cmux`). When the `ro` worker exits `0` with that exact marker as the final line of its final answer (parsed by [`runtime/providers/transcript.py`](../runtime/providers/transcript.py)), the exit monitor relays it as `worker_done`.

### Neutral environment variables

Runtime scripts accept `OPEN_FLEET_*` variables alongside legacy `ORCA_*` aliases. Shared provider helpers prefer a non-empty `OPEN_FLEET_*` value; conflict rejection is helper-specific, not a blanket guarantee:

| Primary (`open-fleet`) | Legacy alias | Purpose |
|---|---|---|
| `OPEN_FLEET_RUNTIME` | `ORCA_FLEET_RUNTIME` | Active RPI provider (`orca`, `posix`, `overstory`, `t3code`, `ao`, `superset`, `gastown`, `worktrunk`, `jcode-swarm`, `emdash`, `vibe-kanban`, `paperclip`, `multiclaude`, `openhands`, or `auto`) |
| `OPEN_FLEET_ROOT` | `ORCA_FLEET_ROOT` | Catalog root directory |
| `OPEN_FLEET_STATE_DB` / `OPEN_FLEET_STATE_DIR` | `ORCA_FLEET_STATE_DB` / `ORCA_FLEET_STATE_DIR` | `posix` SQLite state store path or directory |
| `OPEN_FLEET_SANDBOX_PROFILE` | `ORCA_SANDBOX_PROFILE` | Worker sandbox profile (`ro`, `rw`, `danger`) |
| `OPEN_FLEET_PARENT_PROFILE` | `ORCA_PARENT_PROFILE` | Parent worker profile enforcing monotonic narrowing (`ro < rw < danger`). Set, with the sandbox profile, to the worker's own profile in every `posix` launch; on every runtime `spawn_worker.sh` also records each launch's profile under its pane handle (`~/.open-fleet/spawn-profiles/`, read back through the pane's `ORCA_TERMINAL_HANDLE`), reserving it before the launch (an unwritable registry refuses the spawn), and recording the worker's pane root process, so a spawn inside the worker's pane process tree is capped by its ancestry even when its harness drops `ORCA_*` (see `spawn_identity.py` in the runtime scripts reference for what it does not identify); a session nothing identifies is capped at any unrecorded reservation, and inside a provider's process tree at the live workers, unless it is an anchored coordinator. A session carrying worker identity (`*_DISPATCH_ID`, `*_WORKER_ID`, `*_UNIT_WORKTREE`) but no profile is capped at `ro`, and a capped session cannot use a command override. These are the worker's own environment and files: a guard on the spawn path, not a sandbox (W4-04) |
| `OPEN_FLEET_COORD_ALLOW_AUTONOMOUS_WRITE` | `ORCA_COORD_ALLOW_AUTONOMOUS_WRITE` | Explicit coordinator opt-in (`=1`) required before `spawn_worker.sh` launches a `PROFILE=rw` worker |
| `OPEN_FLEET_COORD_ALLOW_DANGER` | `ORCA_COORD_ALLOW_DANGER` | Explicit coordinator opt-in (`=1`) required alongside a placement-bound recipe before launching `PROFILE=danger` |
| `OPEN_FLEET_SANDBOX_RECIPE` | `ORCA_SANDBOX_RECIPE` | Certified disposable sandbox recipe ID for `PROFILE=danger` (`sandbox_doctor.py --require-placement`) |
| `OPEN_FLEET_UNIT_WORKTREE` | `ORCA_UNIT_WORKTREE` | Active worker worktree boundary enforced by `deny-hook.sh` |
| `OPEN_FLEET_GATE_MANIFEST` / `OPEN_FLEET_MANIFEST` | `ORCA_MANIFEST` | Evidence manifest path read by `verify-gate.sh` |
| `OPEN_FLEET_UNIT_CLASS` | `ORCA_UNIT_CLASS` | Unit class (`mutation`, `report-only`, `planning`) |
| `OPEN_FLEET_EGRESS_LEDGER` | `ORCA_EGRESS_LEDGER` | Hash-chained egress receipt ledger path (`egress.py`) |
| `OPEN_FLEET_DECISIONS_FILE` | `ORCA_DECISIONS_FILE` | Decisions audit log path (`decisions.py`) |
| `OPEN_FLEET_WORKER_ENV_DENY` | `ORCA_WORKER_ENV_DENY` | Extra environment names or globs the `posix` provider strips from a worker launch, on top of `WORKER_ENV_DENYLIST` |

---

## Capability matrix and preflight enforcement

[`runtime/providers/capabilities.json`](../runtime/providers/capabilities.json) defines 8 runtime capabilities, each provider's native vs. portable fallback support, and each mission's required capabilities:

| Capability ID | Description | Portable fallback |
|---|---|---|
| `cap:core-orchestration` | Worktree lifecycle, run/task DAG state, worker spawn/fence, and mailbox messaging | `runtime/providers/local_state.py` (SQLite WAL + `git worktree` + `tmux` / `cmux` / `setsid`) |
| `cap:sandbox-vm` | Disposable VM or container isolation for untrusted execution and recipe checks | `posix` only: a Docker `--on <image>` launch, probed for `docker` on `PATH`; [`runtime/scripts/sandbox_doctor.py`](../runtime/scripts/sandbox_doctor.py) certifies recipe transcripts from its portable backends (`docker`, `bwrap`, `gondolin`, `devcontainer`, `hermes-docker`, `apptainer`, `superset-cloud`, `openhands-docker`) |
| `cap:session-search` | Cross-session transcript search for prior-art recall | [`runtime/scripts/search_sessions.py`](../runtime/scripts/search_sessions.py) `--local-harnesses` |
| `cap:browser` | Headless browser DOM snapshot, console/network capture, and CWV/a11y probing | Playwright CLI / Chrome DevTools MCP |
| `cap:mobile-emulator` | iOS Simulator and Android Emulator lifecycle, screenshot, and UI hierarchy dump | `xcrun simctl` (macOS) and Android `adb` |
| `cap:issue-tracker` | Issue and PR enumeration, creation, commenting, and state transitions | GitHub CLI (`gh`) |
| `cap:scheduler` | Recurring cron/interval execution for unattended sweeps | POSIX `crontab` / `systemd-run` / GitHub Actions `schedule` |
| `cap:orca-self-audit` | Live inspection of the `stablyai/orca` binary and `orca skills get` bundle | **None** — exclusive to `orca` (required only by [`pin-it`](../skills/pin-it/SKILL.md)) |

### Running capability preflight

[`runtime/scripts/preflight.py`](../runtime/scripts/preflight.py) verifies mission capability requirements against the active runtime provider and fails closed (exit `2`) when a required capability is missing:

```bash
# A core-orchestration-only mission (ship-it) passes on posix and every other RPI provider:
python3 runtime/scripts/preflight.py --mission ship-it --runtime posix --mode readonly

# pin-it requires cap:orca-self-audit and fails closed on non-orca runtimes:
python3 runtime/scripts/preflight.py --mission pin-it --runtime posix --mode readonly

# Require native provider capabilities without portable fallbacks:
python3 runtime/scripts/preflight.py --mission offload-it --runtime posix --strict-native-capabilities --mode readonly
```

---

## Supported orchestrator providers (14)

All 14 providers implement [`RuntimeProvider`](../runtime/providers/base.py) and return Orca-compatible JSON envelopes so coordinator scripts (`task_ops.py`, `worker_ops.py`, `worktree_ops.py`, `terminal_ops.py`, `send_msg.py`, `check_reply.py`, `hitl_ask.py`, `watchdog.py`) run unchanged. Every adapter preserves worker commits under `refs/open-fleet/preserved/<dispatch>` before cleanup and fails closed on unsupported profiles or unverified harnesses.

A provider's `supported_harnesses` in [`capabilities.json`](../runtime/providers/capabilities.json) lists only harnesses its adapter honors and that `spawn_worker.sh` launches on it. On `orca`, `spawn_worker.sh` has no default launch row for `opencode`, `omp`, or `pi` (Orca strips `opencode`'s permission flag, and `omp` and `pi` are not in Orca's autonomous-argument map), so those three harnesses require a non-`orca` runtime (such as `OPEN_FLEET_RUNTIME=posix`) or an explicit `WORKER_CMD` override. Conversely, the `openhands` SDK agent runs exclusively on `OPEN_FLEET_RUNTIME=openhands` (which refuses CLI harness names, while all other runtimes refuse `openhands`).

### Tier 1 — Primary providers

| Provider | Upstream | Transport | Profiles | Native capabilities |
|---|---|---|---|---|
| `orca` | `stablyai/orca` | Native desktop/CLI control plane | `ro` (not `crush`, `cursor`, `antigravity`, `grok`, `droid`), `rw` (`danger` refused; requires off-`orca` placement binding) | All 8 capabilities including `cap:orca-self-audit` |
| `posix` | `open-fleet/posix` | SQLite WAL + `git worktree` + `tmux` / `cmux` / `setsid`; `danger` = Docker (`--cap-drop ALL`, `no-new-privileges`, private git dir synced on exit) | `ro`, `rw`, `danger` (`danger` refused for `hermes`) | `cap:core-orchestration` (`cap:sandbox-vm` only as a Docker-probed fallback, refused under `--strict-native-capabilities`) |
| `overstory` | `jayminwest/overstory` | `ov sling` / `ov spec write` / `ov mail` | `ro` (`claude`, `pi`), `rw` | `cap:core-orchestration` |
| `t3code` | `pingdotgg/t3code` | MCP `t3_thread_*` tools via `t3 acp-mcp-call` | `ro`, `rw` | `cap:core-orchestration` |
| `ao` | `ComposioHQ/agent-orchestrator` | Loopback HTTP daemon `POST /api/v1/sessions` | `rw` | `cap:core-orchestration` |
| `superset` | `superset-sh/superset` | `superset terminals create` (`ro`), `agents create --prompt` (`rw`) | `ro`, `rw` | `cap:core-orchestration` |

### Tier 2 — Ecosystem adapters

| Provider | Upstream | Transport | Profiles | Native capabilities |
|---|---|---|---|---|
| `gastown` | `gastownhall/gastown` | `gt sling <bead>` + `bd` beads graph, `gt mail`, `gt polecat status` | `ro` (`claude`, `codex`, `gemini`), `rw` | `cap:core-orchestration`, `cap:issue-tracker` |
| `worktrunk` | `max-sixty/worktrunk` | `wt switch --create` + detached `tmux`; `wt remove --reap` after HEAD preservation | `ro`, `rw` | `cap:core-orchestration` |
| `jcode-swarm` | `1jehuang/jcode` | `jcode serve` daemon socket (`comm_spawn` / `comm_read_context` / `comm_stop`) | `rw` (`jcode` only) | `cap:core-orchestration` |
| `emdash` | `generalaction/emdash` | `workspace.sock` framed wire protocol | `ro` (`claude`), `rw` | `cap:core-orchestration` |
| `vibe-kanban` | `BloopAI/vibe-kanban` | REST `POST /api/workspaces/start` + post-exit auto-commit guard | `ro` (`claude`), `rw` | `cap:core-orchestration` |
| `paperclip` | `paperclipai/paperclip` | REST control plane (port 3100) with atomic checkout | `ro` (`claude`), `rw` | `cap:core-orchestration` |
| `multiclaude` | `dlorenc/multiclaude` | Daemon socket `spawn_agent` + `tmux` + `.multiclaude/hooks.json` | `ro`, `rw` (`claude` only) | `cap:core-orchestration` |
| `openhands` | `OpenHands/software-agent-sdk` | Agent-server REST conversations (port 8000) with `openhands` SDK agent | `ro`, `rw` | `cap:core-orchestration` |

### `posix` launch crash recovery

A `posix` `worker-start` crosses six atomic boundaries (`LAUNCH_BOUNDARIES` in [`runtime/providers/posix.py`](../runtime/providers/posix.py)) so a coordinator killed mid-launch (e.g., `SIGKILL` or power loss) reconciles deterministically via `orchestration launch-reconcile` without guessing from process exit codes:

| # | Boundary | Durable state after step | Recovery action on coordinator restart |
|---|---|---|---|
| 1 | `intent_claimed` | Launch intent recorded (`claimed`), task `ready → dispatched`, request `pending` | Releases task claim back to `ready`; marks request `failed` |
| 2 | `worktree_created` | `git worktree add` on `fleet/<name>` + worktree hooks installed | Releases task claim to `ready`; preserves worktree and pins HEAD |
| 3 | `registered` | Terminal and dispatch rows written (`ready`, `pid 0`), phase `registered` | Adopts monitor if it claimed the CAS launch gate (`claim_monitor`); otherwise abandons (`abandon_unlaunched`) |
| 4 | `monitor_spawned` | `setsid`, `tmux`, or `cmux` monitor process started | Adopts monitor if gate claimed and publishes its PID; otherwise abandons |
| 5 | `published` | Monitor PID and backend recorded, phase `published` | Adopts running dispatch or tears down if fenced during startup |
| 6 | `receipted` | Request and intent marked `completed` | Complete; idempotent `--retry-request` replays the stored receipt |

Key recovery invariants (tested across `setsid` and real Docker `danger` containers in [`tests/test_posix_crash_recovery.py`](../tests/test_posix_crash_recovery.py) and [`tests/test_posix_docker_crash.py`](../tests/test_posix_docker_crash.py)):
- **Single monitor CAS gate:** `LocalStateStore.claim_monitor` and `abandon_unlaunched` use mutually exclusive compare-and-set transitions so a late monitor can never start an abandoned dispatch.
- **Lock-fenced ownership:** Active launches hold `<state_dir>/intents/<intent>.lock` (`flock`), and recovery holds `<intent>.recovery.lock`. Passing `--takeover` bumps the epoch so any stale writer fails with `launch_fenced`.
- **Zero data loss on `danger` containers:** Before declaring a crashed Docker `danger` worker dead, reconciliation stops the container and syncs its private git directory back to `refs/open-fleet/sandbox/<dispatch>`.

### `posix` git custody

Every git the `posix` provider runs is coordinator-side over a `.git` a worker can write (linked worktrees share one config and one `info/attributes`; the same uid shares `~/.gitconfig`), so it runs through one custody, `run_git` in [`runtime/providers/posix.py`](../runtime/providers/posix.py) (W4-01):

- **The floor.** [`runtime/scripts/gitexec.py`](../runtime/scripts/gitexec.py)'s absolute git, no global or system config, hooks in `/dev/null`, `core.fsmonitor` off, `diff.external` empty, replace refs and grafts off, stdin closed, plus fixed keys for the commands the provider runs: `core.alternateRefsCommand` (a `fetch` runs it for an alternate the shared `objects/info/alternates` names), no submodule recursion, `log.showSignature=false` with the `gpg.*.program` keys pointed at `/dev/null`, and no auto-maintenance. A fixed key is pinned in the call's own environment, so it cannot be raced. The transport is pinned in the environment, not config: `GIT_ALLOW_PROTOCOL=file` (which git documents overrides any `protocol.*.allow`, so a worker's specific `protocol.ssh.allow=always` cannot re-enable ssh for a `url.ssh://....insteadOf=<sandbox>` rewrite the way it beats a generic `protocol.allow=never`), and `GIT_NO_LAZY_FETCH=1` so an `extensions.partialClone` + `remote.<n>.uploadpack=<payload>` cannot make even a plain `rev-parse <ref>^{commit}` lazily fetch and run the payload — a missing object fails the call instead. The provider's git uses only the local `file` transport (the sandbox clone/fetch from an absolute path).
- **No command that can apply a driver reads the repository's config.** An attribute-selected driver (`filter.<name>.smudge`/`clean`/`process`, `diff.<name>.textconv`/`command`, `merge.<name>.driver`) is named, so it cannot be pinned, and listing the declared names to blank them leaves a window in which a still-running worker adds a new one. So a git that could apply one runs against a git dir the coordinator builds for that call: its own config (no driver at all), the repository's objects as a read-only alternate, and copies of what a `status`/`read-tree` there must read to match the repository's own verdict — its index (with any split-index `sharedindex.<hash>`), `info/sparse-checkout`, `info/exclude`, `info/attributes` (data: line-ending and encoding attributes; a driver one names is undefined there) and `shallow`, the content of the repository's own `core.attributesFile` (read only as a bounded regular file, without blocking; anything else refuses), plus the repository's data-only `core.*` settings (`filemode`, `symlinks`, `ignorecase`, sparse flags, `autocrlf`, ... — not `core.excludesFile`, honouring which could hide a worker's untracked file) as the call's own config pairs. The object format is reproduced; any other `extensions.*` the custody dir cannot honour (a partial clone above all) is refused rather than guessed. `status` (the clean check) and `merge-tree --write-tree` run there and print what they would in the repository. A new worktree's checkout runs there as `read-tree -u --reset` of the branch, with its index installed into the admin entry the repository records for that path (`checkout_worktree`). Plumbing that reads no working-tree content (`rev-parse`, `update-ref`, `worktree add --no-checkout`, `worktree remove --force`, a plain `read-tree`, `ls-files`, `fetch`/`clone` from an absolute path, `log` without a patch) runs as is. Anything else (`commit`, `checkout`, `reset --hard`, `diff`, `add`, an unforced `worktree remove`) is refused, never run.
- **Repository selection.** `-C`, the working directory, `--git-dir` and `--work-tree` are the only way a call names its repository: the variables that would point it elsewhere or inject config, templates or helper programs (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`, the object directories, `GIT_ATTR_SOURCE`, `GIT_CONFIG*`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`) are removed from whatever environment the call is given. A `status` runs only at the top of the work tree the call names, never one `core.worktree` redirects it to.
- **Output is bytes.** git's output is decoded with `os.fsdecode`, so a `\r`, `\r\n`, newline, backslash or non-UTF-8 byte in a path comes back as the same path.

`worktree create` is `worktree add --no-checkout` and then that checkout, so its `post-checkout` hook does not run. `worktree rm` decides from the repository's own `worktree list -z`, never the worktree's `.git` pointer (W4-08): a registered worktree is removed only by `git worktree remove --force`, which refuses a locked worktree and a missing or foreign pointer, and when that list cannot be read (for example, a malformed shared config makes git die, or a git older than 2.36 has no `worktree list -z`) the removal is refused with `worktree_list_unreadable`, with or without `--force`. Without `--force` the custody's clean check decides first, against the admin entry the repository records: a worktree with a checked-out submodule is refused (`git worktree remove` refuses one too), and so is one whose `status` lists anything. The `danger` sandbox is seeded with a plain `read-tree` and never refreshed by the coordinator (the worker's own first `git status` refreshes it), and after a sync the host worktree's index is set to the new HEAD with a plain `read-tree`.

The custody's pieces — the git dir builder, the fixed command keys, `GIT_ALLOW_PROTOCOL=file` and `GIT_NO_LAZY_FETCH=1`, the data-only `core.*` settings and the extension refusal — live in [`runtime/scripts/gitexec.py`](../runtime/scripts/gitexec.py) (`custody_git_dir`, `CUSTODY_FLOOR`, `CUSTODY_ENV`, `custody_settings`), shared with the coordinator-side read tools: `floor_guard.py`, `diff_scope.py`, `hint_provenance.py` and `verify.py`'s executed negative control run their working-tree diffs, merge prediction and control checkout in the same kind of git dir ([runtime scripts](runtime-scripts.md#gitexecpy)).

The external adapters use the same custody: every `git` they launch through the shared runners in [`runtime/providers/_external.py`](../runtime/providers/_external.py) (the dirty check before a removal, the HEAD pin, worktrunk's merge prediction, vibe-kanban's status poll and HEAD log), whatever its subcommand, runs through `run_git`, and t3code's worktree cut uses `checkout_worktree`. Their dirty check counts a checked-out submodule as uncommitted work, because the custody's `status` compares a submodule's recorded commit and never looks inside it (git inspects one with a child git that drops the environment floor and reads the submodule's own config).

**Filtered content (Git LFS, git-crypt).** No clean, smudge or process filter runs, so a worktree the coordinator creates (`posix` `worktree create`, t3code's cut) holds the committed bytes: LFS pointer files, git-crypt ciphertext. Built-in conversions (`eol`, `text`, `ident`, `working-tree-encoding`) from the tree's `.gitattributes`, and the repository's `core.autocrlf`/`eol`, still apply. A worker that needs the smudged content runs the filter itself, inside its own worktree (`git lfs pull`, `git-crypt unlock`), where the command is its own. The coordinator's clean check reads such a file the same way, so a smudged file whose stat changed counts as modified, and the removal is refused rather than losing work.

---

## Supported coding-agent harnesses & sandbox profiles

[`runtime/providers/base.py`](../runtime/providers/base.py) (`build_harness_command`) and [`runtime/sandbox-policy.md`](../runtime/sandbox-policy.md) enforce three least-privilege profiles with monotonic privilege narrowing (`ro < rw < danger`):

| Harness | Binary | `PROFILE=ro` enforcement | `PROFILE=rw` / `danger` enforcement |
|---|---|---|---|
| **Claude Code** | `claude` | `claude -p --permission-mode plan --disallowedTools Edit,Write,MultiEdit,NotebookEdit` | `claude -p --dangerously-skip-permissions` + `PreToolUse` `deny-hook.sh` |
| **OpenAI Codex** | `codex` | `codex exec --json -C <wt> --sandbox read-only -c 'approval_policy="never"'` | `codex exec --json -C <wt> --dangerously-bypass-approvals-and-sandbox` + `deny-hook.sh` |
| **OpenCode** | `opencode` | `OPENCODE_CONFIG_CONTENT='{"permission":{"*":"allow","edit":"deny","bash":"deny","external_directory":"deny"}}' opencode run --standalone` | `opencode run --auto --standalone --format json --dir <wt>` + plugin bridge |
| **Oh My Pi (`omp`)** | `omp` | `omp -p --mode json --cwd <wt> --no-session --no-lsp --tools read,grep,glob,find,ast_grep --approval-mode always-ask` | `omp -p --mode json --cwd <wt> --yolo --trusted-extension omp_pi_deny_bridge.ts` |
| **Pi (`pi-mono`)** | `pi` | `cd <wt> && pi -p --mode json --no-session --no-mcp -ne -na --tools read,grep,find,ls --exclude-tools 'bash,powershell,write,edit,codemode,mcp__*'` | `cd <wt> && pi -p --mode json -e omp_pi_deny_bridge.ts --tools read,bash,edit,write,grep,find,ls` |
| **`jcode`** | `jcode` | `jcode -C <wt> --no-update -q --tools read,agentgrep,ls,session_search,conversation_search,memory,web_search --disabled-tools bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp run` | `JCODE_HOOK_PRE_TOOL=deny-hook.sh jcode -C <wt> --no-update -q --disabled-tools selfdev,desktop_selfdev run` |
| **Goose** | `goose` | `GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin analyze` | `GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin developer` |
| **Hermes Agent** | `hermes` | `HERMES_WRITE_SAFE_ROOT=/dev/null hermes --in <wt> --accept-hooks chat --oneshot -Q --toolsets file,web,session_search` | `HERMES_WRITE_SAFE_ROOT=<wt> hermes --in <wt> --yolo --accept-hooks chat --oneshot -Q --toolsets coding` |
| **Crush** | `crush` | `crush --cwd <wt> --data-dir <wt>/.crush-orca-ro run -q` (write/exec tools disabled) | `crush --cwd <wt> --data-dir <wt>/.crush --yolo run -q` |
| **Gemini CLI** | `gemini` | `gemini --approval-mode plan -p <task>` | `gemini --yolo -p <task>` (worktree/sandbox boundary) |
| **Cursor / Antigravity / Grok / Droid** | `cursor` / `agy` / `grok` / `droid` | Refused on `PROFILE=ro` (`unsupported_profile`: no verified read-only CLI flag) | Refused when a headless task prompt is supplied (`unsupported_prompt`) |

### Cross-harness host constraints & loader quirks

When running coordinators or dispatching workers across multiple harnesses, keep these empirical harness constraints in mind:

| Constraint / quirk | Harnesses affected | How `open-fleet` handles it |
|---|---|---|
| **Skill & context body size limits** | Codex (`AGENTS.md` 32 KiB cap; skill body truncation past ~8 KB), compacting hosts | `scripts/validate.py` enforces strict line budgets (`SKILL.md` body ≤ 110 lines, frontmatter ≤ 34 lines, playbooks ≤ 90 lines, runtime ≤ 160 lines) and deferred phase reads (`read <name>.md`) so activation load stays compact |
| **No default `orca` launch row** (Orca strips `opencode`'s permission flag; `omp` and `pi` are not in its autonomous-argument map) | `opencode`, `omp`, `pi` | `spawn_worker.sh` has no default `orca` launch row for `opencode`, `omp`, or `pi`; dispatch those harnesses on `OPEN_FLEET_RUNTIME=posix` (or pass an explicit `WORKER_CMD` override) |
| **SDK-only agent runtime coupling** | `openhands` | Runs exclusively on `OPEN_FLEET_RUNTIME=openhands` (which refuses CLI harness names, while all other runtimes refuse `openhands`) |
| **No verified headless read-only (`PROFILE=ro`) CLI flag** | `cursor`, `agy`, `grok`, `droid` | Fail-closed in `build_harness_command` (`unsupported_profile` / `unsupported_prompt`); use `claude`, `codex`, `gemini`, `opencode`, `omp`, `pi`, `jcode`, `goose`, `hermes`, or `crush` for unattended worker dispatch |
| **`PROFILE=ro` workers cannot run shell commands to signal completion** | All harnesses under `PROFILE=ro` on `posix` | `worker_start` appends an `OPEN_FLEET_WORKER_DONE <dispatch-id> <succeeded\|failed>` instruction; the exit monitor parses the final transcript line via `runtime/providers/transcript.py` |
| **Slash-command name collisions** | Gemini CLI (`/plan`), hosts with multiple skill packs installed | Invoke missions by their outcome name (`map-it`, `ship-it`, `review-it`) and avoid stacking multiple install paths ([Install guide](install.md#pick-one-install-path-per-host-do-not-stack)) |

---

## Porting or certifying a new provider or harness

Contributors adding or re-certifying a runtime provider (`runtime/providers/<name>.py`) or coding-agent harness in [`runtime/providers/base.py`](../runtime/providers/base.py) follow a five-point **Definition of Done**:

1. **Monotonic profile enforcement (`ro < rw < danger`):** Implement `build_harness_command` so `PROFILE=ro` strips write/exec tools at the CLI flag or config level, `PROFILE=rw` wires `runtime/scripts/deny-hook.sh` (or harness equivalent) to fence edits inside `OPEN_FLEET_UNIT_WORKTREE`, and `PROFILE=danger` requires `OPEN_FLEET_COORD_ALLOW_DANGER=1` plus a placement-bound sandbox recipe (`sandbox_doctor.py --require-placement`). Fail closed (`exit 2`) if the harness cannot enforce the requested profile.

   **`ro` is a tool filter, not a filesystem one, on a shell-capable tier (W4-05, C26).** claude `--permission-mode plan --disallowedTools=Edit,Write,MultiEdit,NotebookEdit` and gemini `--approval-mode plan` block the edit TOOLS, but plan mode auto-approves read-only shell, so without the hook write floor a `ro` worker could still mutate through `Bash` (`sh -c 'echo x > f'`, `git checkout -- .`, `npm install`). codex `--sandbox read-only` and shell-stripped harnesses genuinely bound the filesystem or remove shell execution. To enforce the `ro` write floor on shell-capable tiers, `install_worktree_hooks(..., profile="ro")` (and `deny-hook.sh --settings <worktree> --readonly`, or `OPEN_FLEET_SANDBOX_PROFILE=ro` in the hook environment) arms `OPEN_FLEET_HOOK_READONLY=1` (legacy `ORCA_HOOK_READONLY`), under which the hook denies every write it can see — a redirect, a `tee`, a file-tool edit, an `apply_patch`, in any command the line runs: a `-c` body, a substitution, a program fed to a shell by a pipe, `-s` or a heredoc — regardless of the unit boundary, and denies a shell fed a program it cannot read (`cat f | sh`, `sh < f`, `echo "$(cat f)" | sh`), while read-only shell (`git diff`/`log`, `cat`, `ls`, running tests) still runs. That floor is **defense-in-depth over those channels, not a filesystem sandbox**: a mutation the hook does not model as a write record (`cp`/`mv`/`rm` without a redirect, a package install, an interpreter writing through its own API, a script already on disk run as `sh f`) is beyond it, so a `ro` worker that must be *provably* unable to mutate runs on `codex --sandbox read-only`, a shell-disabled harness, or the disposable sandbox, which is the only true read-only boundary for a shell-capable tier.

   **The deny-hook arming gate (W4-06).** `spawn_worker.sh` runs the arming gate for **every** profile, `ro` included (it used to skip `ro` entirely, so a wired guard went unchecked and a `ro` worker never even saw the warning). With `OPEN_FLEET_DENY_HOOK_SETTINGS` (legacy `ORCA_DENY_HOOK_SETTINGS`) naming the registration, the gate verifies it fail-closed for all profiles. When it is **unset**, `OPEN_FLEET_REQUIRE_DENY_HOOK=1` (legacy `ORCA_REQUIRE_DENY_HOOK`) is checked **first** and refuses on every runtime, before any provider deferral or opt-out: the hardened lock means the coordinator itself verifies a named registration. Otherwise enforcement moves to where the guard is installed. The **posix** provider verifies the registration **inside `worker-start`** — `verify_installed_guard` runs `deny-hook.sh --verify-settings` on the file it just wrote (it exists, names the hook that loads, pins the boundary, answers a deny probe) **after installing it and before the agent process starts**, and aborts the launch with `deny_hook_unverified` if any check fails. The **openhands** provider runs the same check on the `hook_config` the agent-server will execute (`verify_conversation_guard`): the registration after its fail-closed existence prefix must be this repo's hook (its bytes checked by this repo's own copy), pin the conversation's working dir and answer the deny probes in OpenHands' tool names — before the conversation is created for a named worktree, and between creation (`run: false`) and the `/run` that starts the agent for a server-cut worktree, whose `$OPENHANDS_PROJECT_DIR` is known only then; a working dir that is not a local directory refuses too. A `new-child` spawn has no worktree or settings file at the coordinator's pre-launch gate, so `spawn_worker.sh` cannot check one there and **defers** to that verification for these two — ordinary dispatch needs no opt-out. **Residual:** every other non-Orca provider (`overstory`, `t3code`, `ao`, `superset`, `gastown`, `worktrunk`, `jcode-swarm`, `emdash`, `vibe-kanban`, `paperclip`, `multiclaude`) installs the guard without re-verifying it, so the gate proceeds there with a loud `UNVERIFIED … on runtime <name>` warning rather than claiming verification; `OPEN_FLEET_REQUIRE_DENY_HOOK=1` turns that into a refusal. **On Orca** `worker-start` is Orca's own and wires no open-fleet guard, so an unset var **refuses**, for every profile (`ro` too: a shell tier writes past its tool filter, W4-05); `OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK=1` (legacy `ORCA_ALLOW_UNVERIFIED_DENY_HOOK`) is the Orca-lane opt-out to a loud `UNVERIFIED` warning, and REQUIRE overrides that opt-out so an inherited value cannot reopen the warning path.
2. **Worktree preservation before cleanup:** Ensure `worktree-remove` and crash recovery preserve the worker's `HEAD` commit under `refs/open-fleet/preserved/<dispatch>` before deleting any worktree directory.
3. **Completion & transcript contract:** Verify that `rw` workers can invoke `send_msg.py --type worker_done` and `ro` workers emit a parseable final answer for `runtime/providers/transcript.py`.
4. **Declare capabilities & supported harnesses:** Register the provider or harness in [`runtime/providers/capabilities.json`](../runtime/providers/capabilities.json) and [`runtime/providers/certification.json`](../runtime/providers/certification.json) at the honest status tier (`source-only`, `fixture-tested`, or `live-witnessed`).
5. **Run the certification & contract suite:**
   ```bash
   python3 runtime/scripts/certification.py check
   python3 runtime/scripts/first_run.py --profile ro
   python3 runtime/scripts/first_run.py --profile rw
   python3 -m unittest discover -s tests -v
   ```
   To advance a cell to `live-witnessed`, record a container-isolated run per **[Provider & harness certification](certification.md#recording-a-live-first-run)**.

---

## Reproducing a first run on `posix`

You can validate the `posix` orchestration pipeline without spending API tokens using the inert harness, or inside the disposable container harness for live agent runs ([Provider & harness certification](certification.md#first-run-on-a-clean-host)):

```bash
# Inert verification (no live agent or API spend; runs in CI across all posix harnesses):
python3 runtime/scripts/certification.py check
python3 runtime/scripts/first_run.py --profile ro
python3 runtime/scripts/first_run.py --profile rw
python3 runtime/scripts/first_run.py probes
```

For live container-isolated runs (`--worker live`), follow the **[Live harness guide](guides/live-harness.md)** and **[Recording a live first run](certification.md#recording-a-live-first-run)**.
