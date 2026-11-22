# Provider and harness certification

[Documentation](README.md) · [Multi-runtime guide](runtimes.md) · [Runtime scripts](runtime-scripts.md) · [Troubleshooting](troubleshooting.md)

[Multi-runtime guide](runtimes.md) lists 14 orchestrator providers and 14 coding-agent harnesses.
An adapter that exists, and flag construction that a unit test checks, do not show that an
installed upstream ran the route end to end. This page shows how far each advertised route has
actually been proven, and gives a first run you can reproduce on a clean host.

The record is [`runtime/providers/certification.json`](../runtime/providers/certification.json)
(versioned: `record_version`, `recorded`). It has one cell per advertised route:

- **provider cells**: every `(provider, profile, harness)` in
  [`capabilities.json`](../runtime/providers/capabilities.json)'s `supported_profiles` ×
  `supported_harnesses`;
- **harness cells**: every `(harness, profile)` of the shared launch table,
  `build_harness_command` in [`base.py`](../runtime/providers/base.py), for `ro` and `rw`.

Each cell names a tier, the exact upstream version or commit it was certified against, evidence
paths and explicit limitations. An upstream version that nobody recorded stays `unknown`.
[`certification.py`](../runtime/scripts/certification.py) validates the record (`check`), lists
every cell (`matrix [--json]`) and renders the block below (`markdown`).

## How to read a cell

| Tier | What it proves | What it does not |
|---|---|---|
| `live-witnessed` | A real upstream build and a real harness ran the route. The evidence is a `docs/runs/` report whose `RUN:` header records `verifier=GREEN` and that binds under `run_report.py`, and whose own bound artifacts name this exact route (`witnessed.route`). | That later upstream builds behave the same: a pin refresh voids the cell. |
| `fixture-tested` | The fleet's own code for the route runs in CI against an in-repo fixture: a scripted upstream transport, or the inert worker of [`first_run.py`](../runtime/scripts/first_run.py). | Anything about the real upstream build or the real harness binary. |
| `source-only` | The launch or flags were written from upstream source or docs. | That anything drives the route. |
| `unsupported` | The fleet refuses the route before any launch, with the typed refusal in `refusal`. A test pins the refusal. | — |
| `unavailable` | The route is advertised, but this repository has no evidence for it, so its state is unknown. | — |
| `stale` (computed) | The provider's pin moved after certification. The cell no longer claims its recorded tier. | — |

## Live-witnessed results

Six cells are live, all with Claude Code, all from runs that bind in the
[run archive](runs/README.md). Two are on the Orca route, two on the posix route, and two are
the claude harness cells the posix runs exercised. A run that binds is not enough on its own: each live
group's `witnessed.route` quotes whole lines of that run's inventoried artifacts, read at the
run's `inventory_at`. Those lines must name the provider, the profile beside the harness, and the
recorded versions. A group that copies another route's witness is refused (#596 review):

- `orca` `ro`/`claude`: Orca 1.4.239 (`Orca.app`, macOS 27.0.1 arm64) and a native Claude Code
  2.1.304, 2026-10-26, in the [#680 witness](runs/2026-10-26-review-it-orca-ro-680.md), on the
  current row with its `--disallowedTools` set. The lane delivered the preamble by the no-inject
  fallback, because Orca cannot see a native install, and the send receipt proved the turn
  start. After the plan was approved in the pane, Write and Edit stayed out of the toolset.
  Route: the run manifest's `toolchain` line (`Orca 1.4.239`, `Claude Code 2.1.304`,
  `PROFILE=ro`). The 2026-10-13 Linux witness (Orca 1.4.224, the earlier row) stays on record.
- Historical evidence for `orca` `rw`/`claude`: Orca 1.4.224 (`orca-ide`, Ubuntu 24.04.5 arm64)
  and Claude Code 2.1.296, 2026-10-13, in the [ship-it mdtoc run](runs/2026-10-13-ship-it-mdtoc.md).
  This is not a live witness at pinned v1.4.239; the cell is `source-only` until a matching run.
  Only the `WORKER_CMD` override lane was witnessed. On the witness host, the supervised
  `worker-start` lane reported `LAUNCHED_UNUSABLE`. Route: the run's dispatch script
  (`PROFILE="rw"`, `WORKER_CMD="claude --dangerously-skip-permissions"`) and its ledger
  (`orca-ide 1.4.224`, `Claude Code 2.1.296`).

- `posix` `ro`/`claude` and `rw`/`claude`: Claude Code 2.1.304 (`claude-opus-5-5`), catalog
  `b96d47e335`, 2026-10-24, in the [live first runs](runs/2026-10-24-review-it-first-run.md).
  Each profile ran GO on two hosts: the dev Mac through an isolation wrapper, and a fresh
  `ubuntu:24.04` container on the same Mac's OrbStack. Those are two hosts on one machine, not
  separate hardware. Route: each receipt's `witness` line (`posix/setsid PROFILE=<p>
  harness=claude version=2.1.304 (Claude Code) … catalog=b96d47e3…`).
- `claude` `ro` and `rw` (the harness cells): base.py's claude line, run by those same posix runs.
  The harness's `upstream.version` is `2.1.304`. Orca runs spawn_worker.sh's own rows, so an
  Orca witness certifies no harness cell.

The Orca pin is now v1.4.239: a source-delta re-witness whose `pins.json` `live_receipts` are
1.4.239's own (the CLI capture and the `ro`/`claude` witness above). The `rw` cell's 1.4.224
witness predates them, so that cell is `source-only` and its old run is historical evidence only.
The record is certified against the pin's three-part fingerprint. No other provider and no other
harness has a live witness.

## Fixture (mocked) results

All other cells that are neither refusals nor Orca's 13 `source-only` cells use fixtures. They
show that the fleet's side of the route works. They do not show how the upstream build or the
harness behaves:

- **posix** (`ro` and `rw`, the 9 harnesses other than `claude`, which is live):
  `first_run.py` drives the whole route through the public wrappers. An inert stand-in answers to each harness name, in that harness's own output
  format as read from its source. Every combination runs in CI.
  `danger` uses a scripted fake `docker`. The provider is this repository's own code, so each CI
  run certifies the commit it runs at.
- **the 12 external adapters**: they use scripted upstream transports. Nobody recorded which
  upstream revision each adapter was read from, so every one reads `unknown`. The certification
  test drives every non-refused cell to its first upstream call, and every refused cell to its
  typed refusal with no upstream call.
- **harness launch lines**: the flags were read from source. Only the inert stand-in has run
  them.

<!-- BEGIN GENERATED: certification-matrix — runtime/scripts/certification.py markdown -->
Record version 7 (2026-11-19). Counts are cells: one (provider, profile, harness) or (harness, profile) route each.

| Provider | Upstream certified against | live-witnessed | fixture-tested | source-only | unsupported | unavailable | stale |
|---|---|---|---|---|---|---|---|
| `ao` | unknown |  | 11 |  |  |  |  |
| `emdash` | unknown |  | 11 |  | 9 |  |  |
| `gastown` | unknown |  | 10 |  | 4 |  |  |
| `jcode-swarm` | unknown |  | 1 |  |  |  |  |
| `multiclaude` | unknown |  | 2 |  |  |  |  |
| `openhands` | unknown |  | 2 |  |  |  |  |
| `orca` | v1.4.239 (47f77cf7018e) | 1 | 2 | 14 | 16 |  |  |
| `overstory` | unknown |  | 9 |  | 5 |  |  |
| `paperclip` | unknown |  | 3 |  | 1 |  |  |
| `posix` | in-repo | 2 | 27 |  | 1 |  |  |
| `superset` | unknown |  | 14 |  |  |  |  |
| `t3code` | unknown |  | 4 |  |  |  |  |
| `vibe-kanban` | unknown |  | 7 |  | 5 |  |  |
| `worktrunk` | unknown |  | 20 |  |  |  |  |

| Harness | Upstream version | live-witnessed | fixture-tested | source-only | unsupported | unavailable |
|---|---|---|---|---|---|---|
| `antigravity` | unknown |  |  |  | 2 |  |
| `claude` | 2.1.304 | 2 |  |  |  |  |
| `codex` | unknown |  | 2 |  |  |  |
| `crush` | unknown |  | 2 |  |  |  |
| `cursor` | unknown |  |  |  | 2 |  |
| `droid` | unknown |  |  |  | 2 |  |
| `gemini` | unknown |  | 2 |  |  |  |
| `goose` | unknown |  | 2 |  |  |  |
| `grok` | unknown |  |  |  | 2 |  |
| `hermes` | unknown |  | 2 |  |  |  |
| `jcode` | unknown |  | 2 |  |  |  |
| `omp` | unknown |  | 2 |  |  |  |
| `opencode` | unknown |  | 2 |  |  |  |
| `pi` | unknown |  | 2 |  |  |  |

Live-witnessed cells (everything else is fixture, source or refusal evidence):

- `orca` ro/claude: upstream Orca 1.4.239, Claude Code 2.1.304, macOS 27.0.1 arm64 (the dev Mac), 2026-10-26 — [2026-10-26-review-it-orca-ro-680.md](runs/2026-10-26-review-it-orca-ro-680.md)
- `posix` ro/claude: upstream b96d47e3354564e1593d34182a817ae04e54545d, 2.1.304 (Claude Code), macOS 27.0.1 arm64 (dev Mac, isolation wrapper) and Ubuntu 24.04.5 aarch64 (fresh ubuntu:24.04 container on the same Mac's OrbStack), 2026-10-24 — [2026-10-24-review-it-first-run.md](runs/2026-10-24-review-it-first-run.md)
- `posix` rw/claude: upstream b96d47e3354564e1593d34182a817ae04e54545d, 2.1.304 (Claude Code), macOS 27.0.1 arm64 (dev Mac, isolation wrapper) and Ubuntu 24.04.5 aarch64 (fresh ubuntu:24.04 container on the same Mac's OrbStack), 2026-10-24 — [2026-10-24-review-it-first-run.md](runs/2026-10-24-review-it-first-run.md)
- `claude` ro/claude: upstream b96d47e3354564e1593d34182a817ae04e54545d, 2.1.304 (Claude Code), macOS 27.0.1 arm64 (dev Mac, isolation wrapper) and Ubuntu 24.04.5 aarch64 (fresh ubuntu:24.04 container on the same Mac's OrbStack), 2026-10-24 — [2026-10-24-review-it-first-run.md](runs/2026-10-24-review-it-first-run.md)
- `claude` rw/claude: upstream b96d47e3354564e1593d34182a817ae04e54545d, 2.1.304 (Claude Code), macOS 27.0.1 arm64 (dev Mac, isolation wrapper) and Ubuntu 24.04.5 aarch64 (fresh ubuntu:24.04 container on the same Mac's OrbStack), 2026-10-24 — [2026-10-24-review-it-first-run.md](runs/2026-10-24-review-it-first-run.md)
<!-- END GENERATED: certification-matrix -->

### What the record surfaces

The first run surfaced five defects, and record version 3 records them fixed (#596). The tiers did
not move up: every changed cell is still `source-only` or `fixture-tested`, or is now a refusal.

- **Orca read-only rows for `jcode` and `hermes` now carry base.py's restriction.** jcode gets
  its `--tools` allowlist and the full `--disabled-tools` set, `replace` included. hermes gets
  `HERMES_WRITE_SAFE_ROOT=/dev/null` and `--toolsets file,web,session_search`. A test holds both
  to base.py's flags, but nothing runs them against Orca, so the cells stay `source-only`.
- **Orca `ro` for `crush` is refused.** No flag makes crush read-only. Its read-only mode is a
  `crush.json` in its data dir, and only the posix provider writes that file. The Orca lane
  installs nothing, so the wrapper refuses rather than launch an auto-approving `crush run`.
- **`opencode`, `omp` and `pi` are no longer advertised for Orca.** spawn_worker.sh has no Orca
  row for them, so `capabilities.json` stopped claiming them and their nine cells left the
  record. `tests/test_capability_launch_agreement.py` fails if a claimed provider/harness pair
  does not launch through the wrapper.
- **A posix `ro` worker can report completion.** Where an exit monitor runs, its assignment
  names the line `OPEN_FLEET_WORKER_DONE <dispatch-id> <succeeded|failed>`. When that line ends
  the worker's final answer, the monitor relays it as the worker's `worker_done`. The final
  answer is read per harness by the same reader as the first-run report, so a marker in
  reasoning, in a tool result or in an echoed prompt does not count. The inert stand-in prints the line in each harness's
  own output shape, so `first_run.py --profile ro` settles `completed`. A worker that does not
  print it still settles `worker_died (exit=0)`, and the run accepts either. In the unbound
  2026-10-24 live `ro` run, Claude Code 2.1.304 printed the line too and the unit settled
  `completed`.
- **gastown's claude `ro` alias carries `--disallowedTools`.** Every claude `ro` launch line the
  fleet builds (`base.py`, `spawn_worker.sh`'s Orca row, the gastown alias, emdash's `extraArgs`)
  carries `Edit,Write,MultiEdit,NotebookEdit`, and multiclaude denies the same tools (plus `Bash`)
  in the worker's `.claude/settings.json`; vibe-kanban, t3code and paperclip rely on the
  upstream's own plan or approval mode instead, and overstory on its own guard hooks. Orca's
  plan-mode row was the exception until record version 4.

### What record version 4 changes

Version 4 closes the gaps the first live runs and the last review left. No tier moved up.

- **`openhands` launches through the wrapper.** `capabilities.json` claimed `openhands`/`openhands`
  while `spawn_worker.sh` refused the agent name. The wrapper now launches the OpenHands SDK
  agent on `OPEN_FLEET_RUNTIME=openhands` through `worker-start` and requires the profile's
  toolset token (`tools=…`) on the receipt. It refuses that agent on every other runtime, and
  every CLI harness name on the openhands runtime, before any upstream call. The
  launch-agreement test now holds every claimed pair with no exception. The cells stay
  `fixture-tested`: the end-to-end test runs against a loopback stand-in agent-server.
- **The rw first run asks for the report as its final answer.** The live `rw` run failed at
  `result` because its assignment never asked. The inert stand-in is now literal, so the
  fixture catches that kind of gap.
- **Orca's claude `ro` row carries `--disallowedTools` too.** It is plan mode plus
  `--disallowedTools=Edit,Write,MultiEdit,NotebookEdit`, so the set still holds after the
  coordinator's in-pane approval exits plan mode. This is the live-witnessed route. Its cell
  keeps the 2026-10-13 witness with a limitation saying that witness ran the row without the
  set: a fresh Orca witness is owed.
- **The record checks what is copied from a receipt.** A first-run receipt carries a quotable
  `witness` line. `check` refuses quotes of an inert run, refuses a live harness cell that only
  an Orca run witnessed, and checks a harness cell's version, an in-repo provider's catalog
  commit and the witness date. See [Recording a live first run](#recording-a-live-first-run).

### What record version 5 changes

The bound live first runs move four cells to `live-witnessed`: `posix` `ro`/`claude` and
`rw`/`claude`, and the `claude` harness's `ro` and `rw`, whose `upstream.version` is now `2.1.304`.
The other nine posix harnesses stay `fixture-tested`. The Orca `ro`/`claude` re-witness was
attempted and refused at Claude Code's folder-trust prompt, so that cell keeps its re-witness
limitation. The attempt also changed `spawn_worker.sh`:

- a `new-child` or `new-top-level` selector on the Orca ro lane is now refused before any task is
  created;
- a prompt the agent is blocked on is now named in the failure (`blockedReason`).

## A refreshed pin voids cells

A provider bound to a pin carries `upstream.pin` (`<file>#<key>`) and `certified_against`, which
holds the pin's `commit`, `version` and `live_receipts.version`. Today `orca` is the only
provider bound this way. If any of the three values moves, **every cell of that provider reads
`stale`** and `certification.py check` fails with `STALE provider …`. The check stays failed
until a maintainer rechecks the cells, updates them, bumps `record_version` and re-records
`certified_against`.

To preview which cells a re-pin voids before landing it:

```bash
python3 runtime/scripts/certification.py check --pins /path/to/candidate-pins.json
python3 runtime/scripts/certification.py matrix --pins /path/to/candidate-pins.json | grep stale
```

Harnesses have no pins. A harness upgrade cannot void a cell automatically, so each harness cell
says which binary, if any, ever ran.

## First run on a clean host

This is the reproducible path for a fresh clone. The default worker is inert, so the run calls
no model and spends nothing. It drives one review unit through the same wrappers an operator
types: `preflight.py`, `task_ops.py`, `spawn_worker.sh` (on `OPEN_FLEET_RUNTIME=posix`, `setsid`
backend), `worker_ops.py`, `check_reply.py` and `verify.py`. The run ends with a SHA-bound
verdict.

### Prerequisites

| Need | Check | Why |
|---|---|---|
| Python 3.11–3.13 | `python3 --version` | Every runtime script; stdlib only |
| Git | `git --version` | Worktrees, the evidence commits, the verifier checkout |
| bash and POSIX `sh` | `bash --version` | `spawn_worker.sh`, `deny-hook.sh` |
| A full clone | `git rev-parse --is-shallow-repository` prints `false` | `certification.py check` binds live cells with `run_report.py`, which needs history |
| For the live run only: the harness, signed in | `claude --version` | The real worker; this run spends |

The fixture does not need Orca, tmux, Docker or a network connection.

### 1. Inert first run (no agent, no spend)

```bash
git clone https://github.com/ravidsrk/open-fleet.git
cd open-fleet
python3 runtime/scripts/certification.py check
python3 runtime/scripts/first_run.py
```

Expected output, with your own SHAs and paths:

```text
FIRST_RUN=GO
ROUTE=posix/setsid PROFILE=ro HARNESS=claude WORKER=inert TIER=fixture-tested
REVIEWED=<base 40-hex>..<head 40-hex>
EVIDENCE=<contract commit>..<report commit> VERIFY=OK
DISPATCH=disp_<id> TASK=task_<id>
ELAPSED_S=<seconds>
RECEIPT=/tmp/open-fleet-first-run-<x>/receipt.json
```

`REVIEWED` is the reviewed range. `EVIDENCE` is the commit range that `verify.py` re-derived. It
contains only the report, with the frozen contract as its base. The worker gets the reviewed
diff as a file frozen with the contract, because most read-only launches cannot run `git`. Its
report must quote the read receipt that ends the file and name every changed path. Add `--profile rw` to have the
worker commit the report and send `worker_done`; the coordinator re-reads the worker's HEAD from
git and refuses a committed report that does not open with the required line. Add
`--agent <harness>` to run another posix harness name, `--keep` to keep the sandbox, and
`--target <repo> --base <rev> --head <rev>` to review your own range. The target is cloned and
never modified. On a 2026 macOS arm64 development host, one inert run took about 2 seconds. That
is a fixture timing, not a clean-host record.

`receipt.json` records each step with its exit, elapsed seconds and, on failure, a recovery
hint. It also records every command's argv and exit, the host (platform, Python, Git, bash), the
catalog commit, and whether the catalog tree was dirty. After a GO, the sandbox is pruned down to
`receipt.json`. After a NO-GO, the whole sandbox is kept for inspection. Ctrl-C, `kill`
(SIGTERM) or a closed terminal (SIGHUP) stops the run's worker before the command exits; a run
ended that way keeps its sandbox and writes no receipt.

### 2. Negative probes

```bash
python3 runtime/scripts/first_run.py probes
```

Each probe must refuse before any launch. The stand-in never runs and no dispatch is recorded:

| Probe | What it tries | Refusal |
|---|---|---|
| `unsupported-profile` | `PROFILE=ro` for `cursor`, which has no verified read-only launch | `spawn_worker.sh` exit 2 |
| `privilege-escalation` | an `rw` child under `OPEN_FLEET_PARENT_PROFILE=ro` | exit 2, monotonic narrowing |
| `unarmed-deny-hook` | `OPEN_FLEET_DENY_HOOK_SETTINGS` naming a registration that never denies | exit 2, `deny-hook not armed` |
| `malformed-upstream-response` | a runtime CLI that answers with non-JSON | exit 1, `SPAWN=FAILED` before `worker-start` |
| `missing-capability` | `pin-it` on posix, which lacks `cap:orca-self-audit` | `preflight.py` exit 2 |

Expected output: one `PROBE=<name> REFUSED` line per probe, then `PROBES=GO`.

### 3. Live first run (one command per profile)

**Only inside the container-based live harness (PR #668).** Run directly on a host,
`--worker live` is refused, exit 2, before anything is read or created
([`containment.py`](runtime-scripts.md#containmentpy)); the
[live harness guide](guides/live-harness.md#3-run-one-arm) runs it in a fresh container. The
commands below are the ones the live cells were bound with, kept for the record:

```bash
PATH="<harness-dir>:$PATH" python3 runtime/scripts/first_run.py --worker live --agent claude \
  --profile ro --keep --workdir <runs>/ro --json > <runs>/ro.receipt.json
PATH="<harness-dir>:$PATH" python3 runtime/scripts/first_run.py --worker live --agent claude \
  --profile rw --keep --workdir <runs>/rw --json > <runs>/rw.receipt.json
```

Each command runs the same lifecycle with your real `claude`. **It spends**, because a real model
reviews the change. `<harness-dir>` is the directory of the `claude` you mean, such as an
isolation wrapper. The sandbox puts the interpreter's own directory first on `PATH`, so the run
refuses at `prereqs` if that directory holds a different `claude`. `--keep` keeps the sandbox: its
transcript and its verifier manifest are evidence the record quotes. The receipt is labelled
`live-unreviewed`. It becomes certification evidence only after a maintainer binds it in a
`docs/runs/` report and records the cells, as described in
[Recording a live first run](#recording-a-live-first-run).

The first live runs were made on 2026-10-24 at `456051e3ec`, with Claude Code 2.1.304
(`claude-opus-5-5`) behind an isolation wrapper on macOS arm64, `setsid` backend:

- `ro`: **GO**. Plan mode, 3 turns, USD 0.20, 10.8 s end to end. The report named the reviewed
  head and `verify.py` returned OK.
- `rw`: **NO-GO** at `result`, 5 turns, USD 0.22. The worker committed the right report and
  sent `worker_done`, then answered with a one-line summary. The rw assignment never asked for
  the report as the final answer, but `result` reads it there. The assignment now asks for it,
  and the inert stand-in is literal, so the fixture fails the way the live run did whenever an
  assignment omits that ask. The rw run is owed a re-run.

Re-run from the fixed catalog at `b96d47e335`, both profiles went GO on the dev Mac and in a
fresh `ubuntu:24.04` container. Those four receipts are bound in the
[2026-10-24 run report](runs/2026-10-24-review-it-first-run.md), and the `posix` and harness
`claude` cells are now `live-witnessed`.

### The Orca path

The Orca path is the one already witnessed: a `review-it` run through `orca-ide`. The
[review-it Linux witness](runs/2026-10-13-review-it-linux.md) records its prerequisites, the
exact `spawn_worker.sh` lane, the `verify.py` invocation and its GREEN outcome. To repeat it,
follow [Getting started](getting-started.md#your-first-mission-a-review-it-dry-run) with Orca
installed.

That witness predates the `--disallowedTools` set on Orca's claude `ro` row, so the route was owed
a fresh one. Two 2026-10-24 attempts are recorded in the
[live first runs](runs/2026-10-24-review-it-first-run.md). Both launched the current row and both
failed closed before any injection:

- the first stopped at Claude Code's folder-trust prompt;
- the second ran in a worktree that inherits trust. Orca 1.4.229 refused the inject with
  `no_agent_detected` while the pane showed the claude TUI, and the app then restarted as 1.4.238.

The [2026-10-26 witness](runs/2026-10-26-review-it-orca-ro-680.md) ran the current row on Orca
1.4.239 with a native Claude Code 2.1.304, and Write and Edit stayed denied after its plan was
approved. It also established why the inject was refused. Orca proves an agent present by its
pane title or its foreground process name. A native install runs as `versions/<version>`, and an
idle Claude sets no title, so `dispatch --inject` answers `no_agent_detected` (1.4.229 to
1.4.240). For the ro claude row only, `spawn_worker.sh` then confirms the pane: `terminal show`
must name its agent `claude`, and its screen must show Claude's prompt in plan mode. It then
delivers the preamble of a dispatch without `--inject` by `terminal send`, Orca's own nextStep.
Any other screen refuses with exit 2 and nothing is sent. The record takes the witness at the
v1.4.239 pin (#680).

To repeat the witness, first meet these prerequisites:

- **An existing Orca worktree.** The ro lane's `terminal create` cannot create one, so pass
  `path:<abs>`, not `new-child`. For a scratch review unit, register its repository with
  `orca repo add --path <dir>`, and remove it afterwards with `orca project setup-delete --setup <id>`.
- **A folder Claude Code already trusts.** Claude Code 2.1.304 trusts a folder when its
  canonical git root is trusted, or any directory between the folder and that root. For a
  linked worktree, the canonical root is the main repository. Directories above the git root
  never count, so a trusted `~/projects` does not cover a new repository under it. Use a
  worktree of a repository trusted at its real path (not a symlinked one), or open `claude` once
  in the repository root and answer the prompt yourself. The wrapper never answers it.
- **A coordinator identity.** Create a coordinator terminal and Run
  (`orca terminal create --worktree path:<dir>`, then `orca orchestration run-create --from
  <handle>`), and pass `--run`/`--from`.

Then record the launch the run exercises, and dispatch ONE `PROFILE=ro` worker through the same
wrapper:

```bash
ORCA_CLI_COMMAND=orca SW_PRINT_LAUNCH=1 PROFILE=ro \
  bash runtime/scripts/spawn_worker.sh task_x current witness claude > <run-dir>/launch.txt
orca --version > <run-dir>/orca-version.txt; claude --version > <run-dir>/claude-version.txt
PROFILE=ro SP=<scratch> bash runtime/scripts/spawn_worker.sh --mark-ready --run <run> --from <coord> \
  --spec "<the review unit>" path:<dir> <title> claude
```

The worker plans in plan mode. You approve its plan in the pane, and then `Write` and `Edit` stay
denied. Ask it, after approval, to try each once and report what happened, so the run shows the
set holding.

`launch.txt` must read `LAUNCH=claude --permission-mode plan
--disallowedTools=Edit,Write,MultiEdit,NotebookEdit`. Bind the run as the 2026-10-13 run was
bound. Its artifacts need one line naming `Orca` (or `orca-ide`) with its version, Claude Code
with its version, and `PROFILE=ro`, as that run's `toolchain` line does. Then replace the
`orca` `ro` group's `witnessed`, `evidence` and `limitations`. A witness on
an Orca build other than the pinned one also moves `pins.json` `live_receipts`, which voids
every `orca` cell until `certified_against` is re-recorded (see
[A refreshed pin voids cells](#a-refreshed-pin-voids-cells)).

### Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `step=prereqs`, `` `claude` is not on PATH `` | `--worker live` without the harness installed | Install and sign in to the harness, or drop `--worker live` |
| `step=preflight` | Not run from a git repository with Python 3.11+ | Read the `preflight:` line; see [troubleshooting](troubleshooting.md) |
| `step=dispatch`, a `SPAWN=REFUSED` line | An inherited `OPEN_FLEET_*`/`ORCA_*` variable or a profile refusal | The sandbox clears the known ones; read the `SPAWN=` line in the receipt's failure |
| `step=result`, `worker still ready` | The worker did not finish within `--timeout` | `python3 runtime/scripts/worker_ops.py read --dispatch <d> --source transcript` with the sandbox's `OPEN_FLEET_STATE_DB`; raise `--timeout` |
| `step=result`, `report does not open with` | The worker ignored the spec's first-line contract | Read its transcript. A live model must start its answer with the exact `FIRST-RUN-REPORT` line |
| `step=verify` | `verify.py` refused the bound manifest | The receipt's `recovery` field has the exact command and checkout to re-run |
| `certification.py check` fails with `STALE` | The pin moved after certification | Recheck the provider's cells, then re-record `certified_against` (see above) |
| `certification.py check` says a live cell has no binding report | A shallow clone | `git fetch --unshallow`, then re-run |

## Recording a live first run

A live receipt becomes evidence in two steps, both a maintainer's.

1. **Bind the run.** Copy the run's artifacts into `docs/runs/<date>-review-it-first-run/`:
   the receipt, and from the kept sandbox the verifier manifest
   (`verify/.first-run/<run>/manifest.json`), the report and the contract. Bind them in a
   `docs/runs/<date>-review-it-first-run.md` report whose `RUN:` header and inventory bind under
   `run_report.py`, as for any run.
2. **Record the cells.** In `runtime/providers/certification.json`, move the run's cells out of
   their fixture group into a `live-witnessed` group of their own, both the provider cell
   (`posix`, `<profile>`, `claude`) and the harness cell (`claude`, `<profile>`), and fill them
   from the receipt:

| Record field | From the receipt | `certification.py check` requires |
|---|---|---|
| `witnessed.route` | the `witness` line, quoted whole from the bound `receipt.json` | the quotes name the provider and `PROFILE=<p>` beside the harness. A fixture line (`worker=inert`, `tier=fixture-tested`) is refused, and a harness cell needs a provider other than `orca` |
| `witnessed.harness_version` | `facts.harness.version`, such as `2.1.304 (Claude Code)` | quoted in the bound evidence, and naming the harness |
| `witnessed.upstream_version` | `host.catalog_commit` | quoted, and for the in-repo `posix` provider a commit on HEAD's history |
| `harnesses.<h>.upstream.version` | the version number in `facts.harness.version`, such as `2.1.304` | named in `witnessed.harness_version` |
| `witnessed.host`, `witnessed.date` | `host.platform`, and the date of `started_at` | the date is `YYYY-MM-DD` |
| `evidence` | the bound `docs/runs/*.md` report | it binds (`verifier=GREEN`, a self-run or external-run tier) |

A receipt written before the `witness` line existed (the 2026-10-24 `ro` run) is quoted from
three lines instead: the manifest's `claim` line (`… on the posix route (live claude,
PROFILE=ro)`) and the receipt's `"version"` and `"catalog_commit"` lines. Bump `record_version`,
regenerate the matrix with `certification.py markdown`, and run `certification.py check`.

## Recording a clean-host first run

**Recorded 2026-10-24**, in the [live first runs](runs/2026-10-24-review-it-first-run.md), with
one limitation: the host is a fresh `ubuntu:24.04` container on the dev Mac's OrbStack, not
separate hardware. A non-root user installed Claude Code 2.1.304 with the official installer,
cloned the public repository at `b96d47e335`, and ran `ro` then `rw`, both GO. The steps took
15 s for the OS prerequisites (git, curl, ca-certificates, python3, tmux), 14 s for the install,
5 s for the clone, then 11 s and 16 s for the two runs: 61 s end to end. Nothing failed, so
nothing needed recovery. The log, both receipts and the scripts are retained.

A clean-host record counts only when it comes from a host that has not run open-fleet before.
Record:

1. The host: OS, architecture, and how it was provisioned (fresh VM or container image and its
   digest).
2. Prerequisites as found, and anything installed to meet them, with versions.
3. Elapsed time for setup (clone, installs) and for the run. The receipt already carries
   per-step `elapsed_s` and the total.
4. Every failure, verbatim, with the recovery that cleared it.
5. The receipt itself, for the inert run, the probes and, if authorized, the live run, filed
   with a `RUN:` report under `docs/runs/`.

## Not certified yet

- A clean-host record on separate hardware. The recorded one is a fresh container on the dev
  Mac (see [Recording a clean-host first run](#recording-a-clean-host-first-run)).
- Live witnesses for every other provider and for any harness other than Claude Code. Their
  upstream versions stay `unknown` until a run records them.
