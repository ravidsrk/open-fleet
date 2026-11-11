# Changelog

All notable changes to open-fleet are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version source of
truth is `.claude-plugin/plugin.json`. A change not yet released is one file in
[`changelog.d/`](changelog.d/README.md) until the release cut folds it in here; the
`[Unreleased]` entries written before fragments existed were folded in at the 1.0.0 cut.

## [Unreleased]

## [1.1.0] - 2026-11-11

- **Remediation of all 42 adversarial-review findings across verifier, runtime scripts, providers,
  and CI** (#750). `scripts/bundle.py` refuses symlinked files and directories across mission,
  runtime, protocol, plugin, and support-document sources (`C2`). `runtime/scripts/deny-hook.sh`
  validates Python interpreter ownership and non-writability by group/others at both check and
  execution time and leaves `busybox --install [-s] [DIR]` unpeeled (`C18`, `D2`).
  `runtime/scripts/verify.py` and `runtime/scripts/merge_queue.py` pin resolved executable paths,
  hops, and `SHA-256` digests across negative-control and merge-gate phases, isolate merge-gate
  clones via `git init` + direct `fetch` with detached Git config/hooks, scrubbed intermediate
  supervisor environment (`$PPID`), and `bwrap`/`MQ_REQUIRE_GATE_SANDBOX` support, require
  `--execute-nc` by default on reviewed mutation units (with explicit `--allow-static-nc` override),
  replay all eight accepted mutation tools, and verify quiet `oss-contribute` PRs only under a
  digest-bound `"mission": "oss-contribute"` contract (`C10`, `C11`, `C15`, `C19`, `C21`).
  `runtime/scripts/decisions.py` and `runtime/scripts/gate-batch.py` walk past submodules to the
  outermost superproject (`C20`). `runtime/providers/local_state.py`,
  `runtime/providers/posix.py`, and the 12 external orchestrator adapters enforce Run boundaries
  (including launched-worker implicit Run defaults), coordinator-takeover and `"default"`-run
  fencing, pre-side-effect local task claiming (`ready -> dispatched`) and settlement on
  `worker_done`/`merge_ready`, atomic payload-bound request idempotency, ambient-Git-immune state DB
  resolution, strict non-negative terminal/worker cursor pagination with `source`/`truncated`
  metadata, `0600` inbox/message permissions with fence cleanup, and preserved refs on Multiclaude
  release (`C1`, `C24`, `C28`–`C35`, `C37`, `C38`, `C40`). `scripts/live_broker.py` and
  `runtime/scripts/events.py` recover existing spend ledgers on restart (clamping `cap_usd` to prior
  `open` caps) without leaking request fragments and preserve cross-Run conflict state and
  blank-line tamper evidence (`C39`, `C41`, `C42`, `C43`). Mission contracts, docs, fixture
  lockfiles, and regression tests are aligned across `C4`–`C9`, `C12`–`C14`, `C16`, `C17`, `C25`,
  `C26`, `D1`, `D3`, and `T1`.
- **A paste-ready listing kit for the remaining marketplace submissions** (#235).
  [distribution-kit](docs/distribution-kit.md) has a blurb for each aggregator that leads with the
  `proof:` framing (and a test holds its counts to the live rollup), every submission URL, and the
  proof-first replacement blurb for buildwithclaude's stale "10 outcome-named" record. Nothing was
  submitted: each listing still needs the maintainer's own account.
- **The deny hook leaves `busybox --install [-s] [DIR]` unpeeled instead of treating `DIR` as an
  applet** (#740, #750). In BusyBox, `--install [-s] [DIR]` takes an optional target directory
  operand rather than an applet name; `_peel_busybox` peels only leading applet invocations (`busybox
  sh -c '…'`), avoiding false denials when `DIR` matches an applet name.
- **Most CI jobs now run on AWS CodeBuild-hosted runners** (#735). `guard`, `pinned-demo`, the
  install, bind, drift, health, alert and verdict jobs use the `gha-open-fleet` CodeBuild project
  in us-east-1. `tests`, `floor`, `checks`, `gates` and the vf-bench jobs stay GitHub-hosted
  (they need a non-root runner), as do Docker Hub pulls and the release publishers.
  [ops](docs/ops.md#ci-runners) lists the AWS prerequisites, how a fork switches back to
  `ubuntu-latest`, and what a job stuck in "Queued" means.
- **The deny hook closes all eight findings from the 2026-10-29 audit.** A write inside a nested
  body (`sh -c`, `find -exec sh -c`, `xargs sh -c`, sed `e`, awk/perl `system()`) is now held to
  the worktree write boundary (F1). `busybox`/`toybox` shell applets, `hush` included, are judged
  as the shell they run (F2). `git bisect run`, `git rebase --exec/-x` and `git submodule foreach`
  bodies are judged as commands of their own (F3). A `--force-with-lease=<ref>` that does not name
  every pushed ref no longer exempts a forced push (F4). Attached sed `-e'…'` scripts and awk
  `-F`/`-v` operands are parsed as clusters (F5, F6), and `{ receipt; } && send` arms like
  `( receipt ) && send` (F8). Malformed hook events now fail closed: no tool name, a shell event
  with no input, or a command that is neither a string nor a list is refused, and an argv-list
  command is judged as the line it spells (F7).
- **`wtree.sh` fingerprints the repository it is given, and its custody copies can no longer hang
  or be redirected** ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md),
  W4-02 follow-up, Codex round 5). `$(...)` stripped the trailing newline of a repository path
  that ends in one, so `wtree.sh` fingerprinted the repository at the stripped path, a different
  one, and printed its tree. Every path git hands the script (toplevel, git dir, common dir,
  index) and every carried `core.*` value is now read byte-exact; a linked worktree whose path
  ends in a newline fingerprints itself, and a common git dir an alternates file cannot name is
  exit 1. The custody copies (`info/exclude`, `info/attributes`, `shallow`,
  `info/sparse-checkout`, `sharedindex.*`, the index seed and the `core.attributesFile` content)
  were type-checked by path and then opened by `cp` by path again, so a worker that swapped in a
  FIFO in between hung the coordinator and a symlink was followed. Each is now opened once by
  `python3 -I` without blocking or following a final symlink, checked with `fstat` on that
  descriptor, size-capped (16 MiB, 1 GiB for the index and shared index, 1 MiB for
  `core.attributesFile`) and copied from it; anything else is exit 1. `wtree.sh` now needs a
  `python3` on PATH.
- **`spawn_identity.py` decides whose a process is from its credentials, not its `/proc` owner**
  ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md), W4-04, Codex round 10).
  The registration scan skipped every process whose `/proc/PID` was not owned by this uid before
  it tried to read the environment. That owner is the effective uid alone, and root for every file
  of a non-dumpable process, so a same-uid pane running a setuid program read as another user's:
  skipped, the scan "complete", `record-root` answered "no process" (3) and `spawn_worker.sh`
  released the reservation, leaving the pane's scrubbed descendants uncapped. A process now counts
  as this uid's when any of the real, effective, saved and filesystem uids on the `Uid:` line of
  `/proc/PID/status` is this uid; one whose `status` cannot be read or holds no single
  well-formed `Uid:` line leaves the scan incomplete (1, the reservation kept); one none of whose
  uids is this uid is still skipped. New tests isolate the process listing to the process under
  test, so an unrelated unreadable process on the host can no longer supply the expected answer.
- **`search_sessions.py` no longer parses `--current-evidence` in its own process, and the live
  broker's bodies no longer wait on one another for their parses**
  ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md), W5-21, W5-16; Codex
  round 13 on 594f7265). The episodic hint read the frozen task's evidence file under the byte cap
  and then `json.loads`-ed it in the parent before its shape was checked, so a ~60 MiB array of
  empty objects built some 20 million dicts outside the scan's memory limit. The file is now read,
  parsed and shape-checked in a contained child of its own (`SCAN_MEMORY_BYTES`,
  `SOURCE_SECONDS`), as the manifests are, and only the checked observations cross back: at most
  `MAX_OBSERVATIONS` (4,096), each path at most 1,024 characters, within `RESULT_BYTES`. Anything
  else -- unreadable, not UTF-8 JSON, nested past the parser's depth, the wrong shape, past a bound,
  or a parse past a limit -- refuses the hint whole (exit 2), and the library entry holds evidence
  handed to it to the same bounds. No other file `search_sessions.py` reads is parsed in the parent.
  In `live_broker.py`, a body read in full whose JSON values need more budget than it took before it
  was read (13 times its bytes) waited for the rest holding that share, and bodies completed
  together (32 of ~1 MB, ~416 MB of first shares) waited on one another until every one was answered
  503. Now at most one request waits for budget while holding any: of the bodies read in full, one
  may wait for its larger charge, and while it waits every other take leaves what it needs free;
  any other whose charge does not fit at once is answered 503 at once and gives back all of its
  share but its bytes'. A parsed body also gives back its parse's share before it is relayed,
  keeping only its bytes', and on every way out of a request -- an exception included -- the
  bytes' share goes back only once the body's buffer has been freed.
- **The deny hook's write boundary, interpreter table and self-guard close a batch of 2026-10-27
  security-audit findings, and the `ro` tier gains a real write floor** (W1-01..03, W1-05..08,
  W4-03, W4-05, W4-06, W4-09). A leading `~`/`$HOME` is expanded on every write-boundary path, so `echo > ~/.bashrc`
  and a `Write` of `~/.bashrc` are judged where the shell writes, not silently allowed (W1-01); an
  unquoted `$IFS`/`${IFS}` separator is field-split so each candidate head is judged with its
  arguments (W1-02); the inline-interpreter class is closed beyond python/node — the awk family,
  lua/luajit/julia/Rscript `-e`, deno `eval`, a busybox applet, and sqlite3 `.shell`/`.system` and
  sed `e` are read for the shell they launch, awk collects EVERY program source so a benign `-f`
  file never hides a refused `-e` and an unreadable `-f`/`-E` program file fails closed, and an
  arg-taking option (`python -W error`) no longer hides the `-c` after it (W1-03); `tar`/`unzip`/
  `patch`/`cpio`/`pax`/`bsdtar`/busybox reach the self-guard — a guard file named as `tar -cf`/
  `patch -o` output is denied, and an extraction or patch whose destination equals, sits inside or
  contains a guard directory (`tar -C .claude …`, any `-C`/`-d`/`--directory` spelling) is asked,
  with every guard directory and guard file's directory compared wherever its symlinks resolve, so a
  `.claude` linked outside the worktree is still the guard (W1-05); the root/home delete class is normalised rather than spelled out, so `/*/`,
  `~/.`, `${HOME}/*` and `/dev/../` deny (W1-06); `--settings` shell-quotes the hook path and pins
  both boundary names so a space in the install path or a stale inherited variable cannot disarm
  it (W1-07, W1-08); `lexical_abs` no longer pathname-expands a path segment and a glob in a shell
  write target is judged by every path it expands to (W4-09). The spawn arming gate now receives
  the worktree for every selector that names an existing tree, not just `path:` (W4-03), and runs
  for every profile including `ro`, which used to skip it entirely (W4-03). W4-06 now enforces the
  guard where it is installed: the posix provider verifies the registration inside `worker-start`
  — the file exists, names the hook that loads, pins the boundary, answers a deny probe — AFTER
  installing it and BEFORE the agent process starts, and aborts the launch (`deny_hook_unverified`)
  if any check fails, so a `new-child` spawn that the coordinator's pre-launch gate cannot verify
  is still enforced; the openhands provider runs the same check on the `hook_config` its
  agent-server executes, before the conversation exists (named worktree) or before the `/run`
  that starts the agent (server-cut worktree). `spawn_worker.sh` defers to those two and ordinary
  dispatch needs no opt-out; another non-Orca provider, which installs without verifying,
  proceeds with an `UNVERIFIED` warning naming the runtime; on Orca (whose `worker-start` wires no
  open-fleet guard) an unset settings var still refuses, every profile, unless
  `OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK=1` opts out. `OPEN_FLEET_REQUIRE_DENY_HOOK=1` is checked
  before any deferral or opt-out and refuses an unset var on every runtime. A new `OPEN_FLEET_HOOK_READONLY` write
  floor (wired with `deny-hook.sh --settings <wt> --readonly`; no provider sets it on its own)
  lets the hook deny every write it can see on the `ro` tier — in a `-c` body, a substitution or a
  program piped to a shell too, and `echo x > -` writes a file named `-` — and refuse a shell fed
  a program it cannot read (`cat f | sh`, `sh < f`): defense-in-depth over the channels plan-mode
  `Bash` left open, not a filesystem sandbox, which stays the disposable environment's job (W4-05).
- **`wtree.sh` no longer trusts global or system git config**
  ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md), W4-02, W4-07). On a
  one-uid host `~/.gitconfig` is the worker's to write, and a global clean filter both ran in the
  coordinator and chose the fingerprint: it mapped a tampered file back to its committed blob, so
  verify graded a tree no test saw as FRESH. Every staging git call now runs with global and system
  config off; a changed path any declared driver filters (Git LFS included) is exit 3
  (unverifiable), and a global `core.excludesFile` is not read. Inherited
  `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`/`GIT_CONFIG`/`GIT_CONFIG_PARAMETERS` no longer steer
  the fingerprint or blind the driver listing, and git is resolved once to an absolute path.
  Staging (`read-tree`, `add -A`, `write-tree`) now runs in git custody: a git dir wtree.sh builds
  over the repository's objects and work tree, whose config defines no driver, so a filter a
  still-running worker adds after the driver listing neither runs nor chooses the fingerprint;
  a partial clone or a non-regular `info/exclude` is exit 1, and the staged objects no longer
  land in the repository's store. The custody carries the repository's `info/attributes`, the
  content of its own `core.attributesFile` (read only as a regular file of at most 1 MiB, never
  opened blocking; anything else is exit 1) and its line-ending settings as data, so a clean CRLF
  checkout still fingerprints as its tree; no user or system attributes file is opened (a FIFO
  there no longer hangs it); a
  checked-out submodule is never entered by a child git (gitlinks are refreshed with
  `update-index`, so a moved submodule still counts); and a failed exit-3 check is exit 1, not a
  printed tree.
- **The 2026-10-27 security audit's network and egress findings (wave 5) and the bundle half of
  W6-04 are fixed, except the arm's direct network egress (W5-15).** `egress.py` receipts are
  format v2: `id` hashes the record's canonical serialisation and a line must be exactly that
  serialisation, so an extra key, a re-spacing, a type swap or a blank line is TAMPER on the last
  line as on any other, and every line's text, a pre-v2 line's included, is printable ASCII;
  `write` verifies the ledger through the descriptor it holds locked, refuses (exit 3, before the
  send) one the verifier would refuse, streams `--payload-file`, fsyncs, and prints an id that
  `verify --expect-ancestor` (now repeatable) accepts as an anchor, which binds a receipt written
  since the last close; `merge_queue.py` keeps the id of every receipt it writes in its own
  receipts and writes them to the ledger `egress.py`'s default picks. That default is the
  repository root's `.orca/egress.jsonl`; a routed ledger is reported; a `.git` nested below the
  root refuses unless it is a linked worktree whose `.git/worktrees/<name>/gitdir` back-link
  agrees; `grants` verifies first and takes `verify`'s anchors, saying UNANCHORED without one; a
  ledger that is not a regular file (a FIFO) is refused at once by every command, never waited on;
  everything printed is inert; and `verify` finding no receipts exits 4, never 0, unless the run
  declares it sent nothing (`--allow-empty`). Pre-v2
  ledgers keep verifying in the exact v1 form, as a prefix, and the docs say how to recover a
  broken ledger ([runtime-scripts](docs/runtime-scripts.md#egresspy)). `bundle.py`'s ownership
  marker only names candidates: a listed file is deleted once stale only when a build record kept
  outside `--out` (in the clone's git directory) holds its exact bytes, and overwritten only when
  that record holds them, when they are the bytes the build writes anyway, or when they are a blob
  committed in the checked-out commit's history (never another ref) at exactly the source path this
  build copies that file from, so a forged marker with true digests deletes or overwrites nothing,
  inside a mission directory or a user's own skill holding copies of catalog files too; otherwise
  an overwrite refuses and a stale file is left in place and reported. Every check, delete and write walks `--out` from one directory handle
  without following a link, and each overwrite or delete is one atomic exchange or quarantine
  rename whose displaced file must be the exact file checked (inode and sha256) before it is
  destroyed, else it is put back and the build refuses; a marker naming anything a build does not write, carrying a malformed
  name, or that is a symlink or FIFO refuses; a mission that ships `.gitignore`, `.gitattributes`,
  `.gitmodules` or `.git` fails the build; and a `--out` built before digests or without a build
  record refuses once if the build changes anything there ([install](docs/install.md)).
  `external-ci-monitor.py` never re-sends `GITHUB_TOKEN` on a redirect, refuses a foreign origin
  and an oversized body, and shape-checks `--repo`; the paperclip and OpenHands adapters' keys never
  follow a redirect either. The live harness's broker cuts off idle and trickling connections and
  evicts a stalled request when its slots are full -- every wait before a request is read in full,
  for its body budget included, ends at once when evicted -- and a request waiting for body budget
  takes back what a stalled body holds, which goes only to bodies that are arriving, so trickling
  or stalled connections never keep the arm's calls out; it takes no body over the API's own 32 MB, holds each once, and bounds what parsing it
  can allocate before parsing it -- the decoded input and its strings at their characters' width,
  and every JSON value, by a pre-scan that holds no memory of its own and stops after two million
  steps -- and parses it in a child process held to that bound, so the bodies held at once and
  their parses stay within 400 MiB of its 512m container (a body over its share waits, then is
  refused and counted; one whose bound alone could pass that, such as millions of empty objects,
  or whose parse passes its bound, is refused); it bounds `count_tokens`, settles every call, and counts refusals, drops and faults
  per kind with bounded text, so the arm cannot grow the host's ledger. The launcher runs only an
  image whose id its own `build` recorded (from `--iidfile`) from the committed Dockerfile unless
  `--allow-foreign-image` is passed, the committed Dockerfile's digest always the git object's
  (`build` refuses a working copy that differs from HEAD's, before docker reads it and after), and refuses any `--mount` path docker would split; the image
  pins the Claude Code installer and binary by sha256 ([live harness](docs/guides/live-harness.md)).
  `search_sessions.py` reads only regular files (a link, FIFO or device is said, never opened, a FIFO
  or a link to `/dev/zero` named like a transcript included) and
  only a SQLite store's plain tables' stored columns (never a view, virtual table or generated
  column), capped per file and per scan as the bytes arrive, a row's stored size charged as
  SQLite reads it so no value past either cap ever reaches Python, a store over 1 GiB never
  opened (and, on a SQLite without `octet_length`, one over the 64 MiB value cap, so sizing can never
  load a larger value: a bound decided before the open), and SQLite told, before a store's first
  statement, never to load a value or a schema statement past the cap; a `.zst` transcript is walked frame
  by frame in linear work, a damaged tail kept up to its last whole frame and said; a record nested
  past the parser's depth is skipped, never fatal; and a store swapped for a FIFO during SQLite's own
  open fails closed and is said, never hangs recall. Parsing no longer multiplies those byte caps
  past a bound: every scan of the stores and of the run manifests runs in a forked child, which on
  Linux `RLIMIT_DATA` holds to 1 GiB past the process (a source whose parse passes it is skipped
  and said), each source gets 60 s of wall clock on every platform, a child stopped by either is
  restarted past that source, a prior-run hint is assessed and labelled there on its whole record,
  what it returns is a bounded flat JSON projection of what the parent shows and the label, never
  what it parsed, and a store's schema statement is held to 1 MiB everywhere; macOS
  does not enforce `RLIMIT_DATA`, so there only the byte caps and the schema cap bound it. The
  hint's own reads afterwards (`hint_provenance.py`: the re-read of a matched manifest, evidence
  hashing, live files) never follow a final link or block, read only a regular file, and are
  bounded (64 MiB held, 1 GiB hashed as it streams), a refusal being the entry's UNKNOWN reason.
- **The spawn path's identity inputs are bounded: the parent-profile cap reaches Orca workers,
  CLI commands and installer operands are validated, and printed receipt fields are inert**
  ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md): W4-04, W4-10, W4-11,
  W4-12, W4-13, W4-15/W2-03, W2-05/W5-22, W5-19, W5-20). The CLI resolver that `spawn_worker.sh`
  runs first now runs under `python3 -I`, so a caller's PYTHONPATH cannot shadow it.
  `spawn_worker.sh` records every launch's profile under the pane handle the runtime returns
  (`~/.open-fleet/spawn-profiles/`), so a spawn from that pane is capped at it on Orca as well as
  posix. Each launch reserves its profile there before any launch call (an unwritable registry or
  an unset `HOME` refuses the spawn), and registration records the worker's pane root process by
  pid and start time (`spawn_identity.py`), so a spawn inside the worker's pane process tree is
  capped by its ancestry even when its harness drops `ORCA_*`; a session nothing identifies waits on open reservations
  and is capped at any still open, and inside a provider's process tree at the live workers,
  unless it is an anchored coordinator. Every response that names a pane handle (`worker-start`,
  `terminal create`, the `request-show` triage) is read by one extraction before anything judges
  it, wherever the handle sits (an error envelope beside a ready result included, and a response
  that does not parse whole or reads two ways: every occurrence of a duplicated key), and each
  handle is registered whatever the exit code, error code or state; a refused or failed verdict
  prints the pane it names. Registering a pane other than the worker's own (a coordinator-role,
  unknown-role or role-less one) never releases the reservation: only the worker's agent-role
  pane, named and completely recorded, does. Every other reader of a runtime response refuses one that reads two
  ways (a duplicate key, `NaN`, a number that overflows) as unparseable. A session whose
  identity cannot be read is capped at `ro` even when the failing read is one made while it
  waits on a reservation. A launch that may have left a
  worker live without a complete record keeps its reservation; with no handle named, it is
  released only on a response that is exactly one refusal proven to precede any launch effect (a
  strict schema at every level, an allowlist of pre-launch codes, on both launch paths), never for
  a second or nested error, an extra field, `runtime_error`, an unknown or untyped code, or a
  policy refusal that can follow a pane's creation. A process environment the scan
  cannot read (`EACCES`, `EIO`; re-read for a moment first, since a process caught exiting
  answers `EACCES` briefly) leaves the scan incomplete, so finding nothing is unknown, never "no
  process", and the same holds without `/proc` (`ps -E`); a pane that is found is recorded. Any other identity read that fails, a `/proc` of another pid
  namespace included, is unknown rather than absent: the reservation stays, or the caller is
  capped at `ro`. Not covered: a
  worker process outside its pane's process tree whose environment drops the handle (daemonized
  out, run from a process outside the pane, or in another pid namespace), a worker whose `HOME`
  differs, and a pane process that carries no handle; whether a harness does these as ordinary
  behaviour is unwitnessed. A session carrying fleet worker identity with no profile is
  capped at `ro` and a `--parent-profile` flag cannot raise that; a capped session cannot use a
  command override. These are the worker's own environment and files: a guard on the spawn path,
  not a sandbox.
  The title label is bounded and never option-shaped. `OPEN_FLEET_CLI_COMMAND` /
  `ORCA_CLI_COMMAND` must name one executable with no invisible character, and one resolution in
  `orca_cli.py` now serves the Orca provider, `auto`, `preflight.py`, `install.sh` and
  `upstream_probe.py`. `sandbox_doctor.py` reads the recipe from recipe fields only, refuses a
  malformed recipe field, a repeated JSON key and an envelope that contradicts the report at any
  wrapping level or depth (its `metadata` included), reads a report out of every wrapper (up to
  16; more, nesting too deep to parse, and output that opens as JSON by the grammar's first
  token but does not parse are refused, never read as a report or as text), refuses every output shape but one report object (an array, a scalar, a
  list as `result`, a nested or misspelt `backend`), and reads placement claims in every
  spelling. `worker_ops.py`, `terminal_ops.py`, `send_msg.py`, `check_reply.py`,
  `orca_cli.run_json`, `pm.py` and `spawn_worker.sh` print every receipt field, and every error
  and exception message (the provider-dispatch path included), escaped and on one line; no body line, tail item or list row stands at column 0 in the shape of a line those
  printers write (`KEY=`, `---`, `===`, a `(…)` marker, a printer's own `SUBJ:`/`ID:` headers),
  the first body line included;
  a failed sandbox doctor's output and `sandbox_doctor.py`'s reason print escaped; and a lone
  surrogate no longer crashes the printer.
  `send_msg.py` and `check_reply.py` say their sender check catches accidental mismatches only.
  `first_run.py` hands its on-host sandbox an allowlisted environment (locale names by name), so
  no operator credential reaches the worker. `scripts/install.sh` refuses an empty or
  option-shaped `--skills-dir`, ends `mkdir`/`ln` options with `--`, validates mission names from
  the directory entry before any mutation, and names an unset `HOME`.
- **floor_guard, diff_scope, hint_provenance and verify's executed negative control no longer run
  a git driver a worker adds while they read** ([2026-10-27 security
  audit](docs/runs/2026-10-27-security-audit.md), W4-01/W4-02 class). These tools listed the
  filter, textconv and merge drivers the repository's config declared, blanked them, and then ran
  a git that read that config again, so a driver a still-running worker added between the two
  (selected through `.gitattributes` or the shared `info/attributes`) ran on the coordinator.
  The git custody PR #720 built for the providers now lives in `runtime/scripts/gitexec.py`
  (`custody`, `custody_git_dir`, `custody_env`) and the posix provider uses it from there. Every
  content-reading git at these sites runs against a git dir the coordinator builds over the
  repository's objects (and index), whose config defines no driver at all: floor_guard's tracked
  and untracked diffs, diff_scope's working-tree diff and `--predict-merge`, hint_provenance's
  `diff` and `log`, and the control's checkout, revert, apply and seal, whose scratch worktree is
  no longer a linked worktree of the graded repository. The driver listing stays as a belt and
  keeps its fail-closed refusal. Every other git these tools run drops inherited repository
  selectors (`GIT_DIR`, `GIT_INDEX_FILE`, `GIT_EXEC_PATH`, ...) and carries the custody floor
  (`GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL=file`, no signature-verifying child),
  so a planted promisor remote cannot run a payload through a lazy fetch. A repository the custody
  cannot honour (a partial clone) or read safely (a symlinked `info/exclude`) is refused: exit 2
  from floor_guard, `diff_failed` from diff_scope, a `ProvenanceError`, a blocked control. A
  work-tree diff no longer starts a child git inside a checked-out submodule to ask whether it is
  dirty (`--ignore-submodules=dirty`): that child ran under the submodule's own config, so a filter
  planted there ran too. A moved submodule commit is still reported; uncommitted changes inside a
  submodule no longer are. The custody also carries the repository's `info/attributes`, the
  content of its own `core.attributesFile` (read only as a regular file of at most 1 MiB, never
  opened blocking; a FIFO, symlink or larger file refuses; no user attributes or ignore file is
  opened, and no system attributes file except by verify.py's negative control, whose pinned git
  environment does not set `GIT_ATTR_NOSYSTEM`), the content of its own `core.excludesFile` (read
  the same way) and its
  `core.safecrlf`/`core.checkRoundtripEncoding` as data, so a CRLF (`eol=crlf`) checkout no longer
  reads as modified. No repository-named command runs at these sites; a file git would BLOCK on
  is handled best-effort. Before any git runs, floor_guard, diff_scope and hint_provenance refuse a
  repository in which they positively find a config, config include, `commondir` or `shallow`
  that is a FIFO or other non-regular file, checking every spelling of each name a git might
  read (inner whitespace as spaces, verbatim or collapsed; ends trimmed or not; with or without
  `\v`/`\f` as whitespace), without running git and without ever refusing on doubt. Any promisor remote is refused as a partial clone (git 2.43
  never writes `extensions.partialClone`). A blocking file that check misses (one it cannot
  parse, a FIFO swapped in after it, one at a work tree `.gitignore` or `.gitattributes`) blocks
  the git call until its timeout (60 s; up to 120 s in the verifier), and the call is then
  refused. predict-merge reports a custody
  refusal or a timeout as such, hint_provenance any git timeout (custody setup included) as a
  `ProvenanceError`, and verify.py's control a timed-out custody query as its could-not-create
  refusal. Also:
  the `_external.py` runner docstring no longer claims `reset --hard` runs in custody (it is
  refused).
- **`decisions.py --pin-ref` anchors the human grant key only at a ref the checked change cannot
  move** (2026-10-27 security audit, W3-07). `--pin-ref` now takes only a remote-tracking ref
  (`refs/remotes/origin/main`) or a commit id, resolves it once and reads that commit — a local
  branch, tag or `HEAD` is refused, and the ref can no longer move between the check and the read.
  Without `--pin-ref` the working-tree pin is used with a stderr NOTE whether it is present,
  swapped or absent (an absent pin checks one-way grants unsigned), and a caller that sets
  `ORCA_PROVENANCE`/`OPEN_FLEET_PROVENANCE` cannot run at all. The trajectory harness anchors on
  the base commit it recorded instead of its own `main`. Two existing test assertions now name
  `refs/remotes/origin/main` instead of `main` (landed under a one-way floor-guard waiver).
- **Every trust anchor named as a remote-tracking ref resolves by its exact name** (W3-07 class,
  review of the fix above). The anchor sites followed `symbolic-ref`, checked that the target was
  SPELLED `refs/remotes/…`, then let `rev-parse` or `cat-file` resolve it — and git expands a ref
  name (`refs/<name>`, `refs/tags/<name>`, `refs/heads/<name>`, …): with `refs/remotes/worker/key`
  absent, a local branch `refs/heads/refs/remotes/worker/key` answered for it, a revision suffix
  (`refs/remotes/origin/main~1`, `^`, `@{1}`) read an older commit's retired key, and 64 hex digits
  in a SHA-1 clone expanded to a branch of that spelling. `gitexec.remote_tracking_commit` is now
  the one rule: a commit id must name that commit object; a ref must be a full `refs/remotes/…`
  name that `check-ref-format` accepts and that exists under exactly that name, looked up in one
  `for-each-ref` listing and peeled to a commit once. Every symbolic hop must be remote-tracking
  too, and each is read on its own (`git symbolic-ref --no-recurse`, git 2.39+; without it a
  symbolic name is refused): the listing's `%(symref)` is the chain's resolved END, so
  `refs/remotes/worker/key -> refs/heads/bridge -> refs/remotes/origin/<old key>` used to pass
  with the local bridge — the checked change's to re-point — unseen (review round 2).
  `decisions.py --pin-ref`, `gate-batch.py --pin-ref`, `run_report.py`'s trusted base, `verify.py`'s
  trust keys and `release_check.py`'s gate-1 anchor call it; `verify-gate.sh` mirrors it in sh.
  Each planted exploit — the absent-remote local branch, the suffixes, the hex-named branch — had
  verified a worker's key, bound a report the PR's own policy judged, or passed gate 1.
- **The base verify.py, floor_guard.py and diff_scope.py read against is resolved by exact name,
  once** (W3-07 class, second review). `verify.py`'s ancestry, base-binding and `--symbol` checks
  probed `refs/remotes/origin/<base>` and then handed the NAME to `merge-base` and `git grep`: with
  the ref absent, a local `refs/heads/refs/remotes/origin/main` holding a worker's poison commit
  passed both the ancestry proof and the base binding on a sound lane, and a symbol the worker
  committed read as on base. `floor_guard.py` and `diff_scope.py` resolved `--base` (and
  origin/HEAD's target, cut to the short `origin/<x>`) with `rev-parse`, which tries tags and
  local branches first: a tag or local branch spelled `origin/main`, an origin/HEAD pointed at a
  local branch, a suffix such as `origin/main~1`, or the absent-remote local spelling made
  `floor_guard` read a planted waiver (`clean (1 waived)`) and `diff_scope` diff against the
  change's own tip (the AUTH lens off). All three now resolve once through
  `gitexec.remote_tracking_commit` (`gitexec.base_commit` for the two diff tools, where a bare
  local branch name such as `main` is refused on a lane claiming soundness — `ORCA_PROVENANCE` /
  `OPEN_FLEET_PROVENANCE` set — and elsewhere stays usable by its exact name with an advisory
  NOTE), and every later diff, waiver, pin, merge-base and grep read names the resolved commit.
  `run_report.py`'s grading base, used only on the advisory lane, now says so.
- **The anchor listing cannot be split by a line break in a branch name, and every anchor read
  ignores replacement objects and grafts** (W3-07 class, independent re-attack). The
  `for-each-ref` listing was parsed with `str.splitlines()`, which breaks on U+2028, U+2029 and
  U+0085 — all legal in a refname — so a fetched branch `x<U+2028>refs/remotes/origin/main` at the
  worker's commit replaced the real origin/main at every Python site (a swapped pin accepted, an
  unmerged head on base, gate 1 passing). Records now end in NUL+LF and split on that alone; a
  malformed record or a refname seen twice refuses the listing. `run_report.py` ran git under the
  ambient environment, so `git replace`, `git replace --graft` or `.git/info/grafts` made the
  trusted base read the PR's own policy; it, `release_check.py`'s gate 1 and `verify-gate.sh`'s
  key discovery now run git with replacement objects and grafts off. Off a sound lane
  `floor_guard.py` and `diff_scope.py` accept `--base HEAD` and an abbreviated commit id (read as
  an object id, never a branch of that spelling) with the advisory NOTE.
- **The control plane no longer imports a graded tree's stdlib-named siblings, and on a sound
  lane it reads trust keys only at a commit id or the coordinator's own remote-tracking refs**
  (2026-10-27 security audit, W3-01 to W3-11 but W3-07, which has its own entry). A committed
  `runtime/scripts/json.py`
  used to be the verifier's `json` and turned a stale-review RED into GREEN (W3-01, P0): every
  control-plane entry point now drops its own directory from `sys.path` before any other import,
  `verify-gate.sh` runs the verifier with `-I`, `preflight.py` and `orca_cli.py` no longer put the
  repository root on `sys.path`, and `tests/test_entrypoint_guard.py` plants every stdlib module
  name beside all 26 of them and at the root. The gate reads `.orca/dispatch-pubkey` only where a
  ref's final target is remote-tracking — `origin/HEAD`'s (W3-02, P1) or `origin/<base>`'s — and,
  in a fresh CI checkout, at the pull request's base commit (W3-08); on any lane claiming soundness
  `verify.py` refuses a bare-path, local-ref or symbolic-to-local trust key (a record with such a
  key opens no enforcement lane, only the advisory one), reads it at the one
  commit its ref resolves to, and every NOTE says where the key came from (W3-03). A
  remote-tracking or commit key pin is trustworthy only where the worker cannot write refs — the
  coordinator's own fetch or a CI checkout — and every NOTE now says so; in a worker's own clone
  `git update-ref` moves `refs/remotes/*` too, so that lane stays advisory. A retention receipt
  binds the manifest's path as well as its digest (W3-04); `run_report.py` reads the mutation-unit
  list where it reads the key, not at the graded commit (W3-05), and on a lane claiming soundness
  reads both only against a commit id or a remote-tracking base — never a local `main` or an
  `origin/HEAD` pointed at a local branch — and exits 2 when there is none; once `.orca/human-grant-pubkey`
  is pinned a gate-batch answer needs the human's signature or it stays owed, a sound lane must
  name `--pin-ref`, and the release gate reads the key at `refs/remotes/origin/main` and runs
  `render --check` (W3-06). `gate-batch.py --pin-ref` takes only a commit id or a remote-tracking
  ref and reads the set of gates at the same commit as the key: a gate the anchor carries that the
  batch dropped, renamed or re-worded is listed owed — shown from the anchor's record — so
  `"gates": []` no longer passes the release gate, which also fails when main carries no store or
  carries a view the release deleted.
  A worker-writable `gitleaks` is not run on any lane claiming soundness
  (W3-10), and a toolchain file that changes while the verifier runs fails the run (W3-11).
  Committing the dispatch pubkey that switches enforcement on stays a human's step (W3-09, see
  [the verify gate](docs/verify-gate.md#signed-dispatch--what-it-binds-and-where-the-key-comes-from-135)).
- **The posix provider and the external adapters no longer run a command a worker plants in git
  config** ([2026-10-27 security audit](docs/runs/2026-10-27-security-audit.md), W4-01). The
  posix provider ran a bare `git` with the coordinator's whole environment on `worktree add`,
  `worktree remove` and the `danger` sandbox sync, and the adapters did the same for their dirty
  check, HEAD pin, t3code's worktree cut and worktrunk's merge prediction, so a
  `core.hooksPath`/`post-checkout`, a `core.fsmonitor`, a `filter` smudge command or a merge driver
  written into the shared `.git/config` (or the same-uid `~/.gitconfig`) ran as the coordinator.
  Every such git now runs through one custody (`run_git` in `runtime/providers/posix.py`):
  `runtime/scripts/gitexec.py`'s floor plus fixed keys for `fetch`'s alternate-refs command,
  submodule recursion and signature verification, and `GIT_ALLOW_PROTOCOL=file` +
  `GIT_NO_LAZY_FETCH=1` in the environment so a per-protocol `protocol.ssh.allow=always` or an
  `extensions.partialClone` + a promisor remote's `uploadpack` cannot run a payload the config names. A git
  that could apply a filter, diff or merge driver (the clean check, the merge prediction, a new
  worktree's checkout) runs against a git dir the coordinator builds, whose config declares no
  driver, so a worker cannot add one between a check and its use; it carries the repository's
  index (with any split-index shared file), sparse-checkout and data-only `core.*` settings so a
  clean worktree still reads clean, and refuses an `extensions.*` it cannot honour. Any other
  driver-applying git is refused. A worktree
  the coordinator creates therefore holds the committed bytes (LFS pointer files, git-crypt
  ciphertext) and runs no `post-checkout` hook, and the adapters' dirty check counts a checked-out
  submodule as uncommitted work. Also: git output is decoded byte-for-byte, so a `\r` or non-UTF-8
  byte in a worktree path no longer hides a registered worktree from `worktree rm` (W4-08),
  `gitexec.py` and `diff_scope.py` drop an inherited `GIT_CONFIG`/`GIT_CONFIG_PARAMETERS`, which
  blinded the driver listing or outranked the floor (W4-07), `worktree rm` decides from the
  repository's own worktree list and refuses when that list cannot be read (W4-08),
  `diff_scope.py` fails closed when git is absent at import (W4-14), `wtree.sh predict-merge` runs
  `python3 -I`, a `-`-leading `terminal send` text reaches tmux/cmux, `--key=value` and `--` are
  understood and only the dispatcher's own `--json` option is consumed, a non-identifier launch
  env key is refused (W2-01, W2-02), and nine git call sites refuse an option-shaped revision
  (W2-04).
- **CI and the release pipeline no longer let a pull request grade itself** (2026-10-27
  security audit, W6-01 to W6-17). `verdict-gate`, which runs `main`'s copy of
  `scripts/verdict_check.py`, now fails a PR that changes the CI grader (`.github/workflows/`,
  `.github/actions/`, `.github/ci-tools.lock`) unless the repository owner opened it, and a GO
  counts only from an OWNER, MEMBER or COLLABORATOR review, so neither an outsider's APPROVED
  review nor a fork author's GO on their own PR does; [ops](docs/ops.md#merge-gate) says what
  a green gate proves and records the fork-token read-back. The coverage floor no longer reads a
  `.coverage.*` file planted in the PR's tree (coverage remains the PR's own measurement of
  itself, an accepted residual); `.gitleaks.toml` is on the floor guard's frozen surface, the
  secret scan ignores the tree's `.gitattributes` and reads every file as text (a binary one
  included), and its canary proves no waiver covers a
  top-level directory wholesale (a narrower allowlist is the floor guard's to stop); no checkout keeps its token; every
  `uses:` and every demo-stack image is pinned by test, and every workflow must stay in the
  block YAML subset those tests and release gate 3 read line by line. The publishers check the tag before
  fetching it, `release.yml` marks only the newest tag Latest, and `publish-dist` stages the
  bundle exactly. `gen-badges.py` checks a claimed cut's badge and the release commit's shape,
  release gate 3 counts only an unconditional step (no `needs:`, matrix, reusable workflow or
  container) of a pull-request workflow whose whole
  `run:` is the script under python3, bash or sh and nothing else, gates 0 and 4 read CI on the branch
  being cut, and both bookkeeping writers refuse raw HTML and a link scheme that runs or reads
  something (javascript, vbscript, data, file), however it is escaped.
- **The trajectory replay's git calls now ignore a filter selected from `.git/info/attributes`.**
  `scripts/_trajectories.py` read attributes from the empty tree (`GIT_ATTR_SOURCE`), but a
  `$GIT_DIR/info/attributes` line outranks that, so a filter declared in the replay repo's
  `.git/config` and selected there ran on the replay's `add -A`. A recording cannot write the git
  dir today (the replay refuses it), so this closes the second layer: every replay git call after
  `init` now blanks the drivers the repo's config declares, as the verifier gates do. A test plants
  both files behind the write guard and carries a mutation control.
- **Reading a worker's checkout for episodic hints no longer runs a command the checkout names.**
  `runtime/scripts/hint_provenance.py` diffed the live working tree under the hardened git
  environment but without `gitexec.driver_blanks`, so a clean filter the worker declared in its
  own `.git/config` and selected from `.git/info/attributes` ran on the coordinator whenever a
  hint's currency was checked (the #629 channel). Every `diff` and `log` it runs now blanks the
  repo's declared filter, diff and merge drivers, every git call closes stdin, and a config it
  cannot read is a `ProvenanceError` rather than a diff with nothing blanked.
  `tests/test_gitexec_config_commands.py` pins it with a planted filter and a mutation control.
- **Images and the demo moved out of the repository root.** `assets/` is now
  [`docs/assets/`](docs/assets/) (diagrams, badges, brand images and the diagram generator),
  and `demo/` is now [`evals/demo/`](evals/demo/) (the negative-control demo and the target
  app). Run the demo with `sh evals/demo/negative-control/run.sh` and the generator from
  `docs/assets/diagrams/generator/`. The README badges read `docs/assets/badges/`; the
  last-release badge check still reads a pre-move release at `assets/badges/`.
- **The repository root carries fewer files.** `CONTRIBUTING.md`, `SECURITY.md` and
  `CODE_OF_CONDUCT.md` moved into `.github/` (GitHub still finds all three there), and the
  `REVIEW.md` redirect stub is gone (the review it pointed to is
  [`docs/reviews/2026-09-11-review.md`](docs/reviews/2026-09-11-review.md)).
  Links to the old paths from outside the repository no longer resolve.
- **Greptile is no longer part of the merge gate.** `main` now requires `gates`, `guard`,
  `pinned-demo` (GitHub Actions) and `verdict-gate`; `Greptile Review` was dropped on 2026-10-27,
  after Greptile's reviews had stopped posting anything but a neutral "Review paused" check.
  [ops](docs/ops.md#merge-gate) records the new read-back, and the account inventory marks
  Greptile removed.
- **The living docs were audited claim by claim against the code and brought back in line.**
  Each fix rests on the code line it cites; historical records are untouched. The entry points no
  longer name an `OPEN_FLEET_HARNESS` variable (a worker's harness is the `[agent]` argument of
  `spawn_worker.sh`, its profile `PROFILE=ro|rw|danger`), the README's sample transcript prints
  what `preflight.py` and `verify.py` really print, and the FAQ says which missions still use Orca
  off it. Nine mission contract cards were re-rendered to their SKILL.md gates and phases, and the
  `offload-it`, `field-test-it`, `pin-it` and `map-it` compatibility fields corrected. One real
  bug: `reshape-it` ranked churn with `git log --since=90d`, which git silently ignores, so it
  counted all history; it now uses `--since=90.days.ago`. The runtime policies, the runtime
  scripts reference, the verify gate, runtimes, certification, concepts, evals, bench and
  governance docs had their flags, exit codes, env aliases, source ranges, counts and pins
  corrected. Comments and help text in ten runtime scripts now say what the code does, as do two
  printed messages (`floor_guard.py`'s base-ref error names all five refs it tries, and
  `verify.py`'s class-downgrade NOTE no longer says tests are exempt); no behavior changed.
- **A repository-wide adversarial review closed the bypasses it reproduced and fixed the drift
  it found.** `deny-hook.sh` now expands brace expressions and reads `git -c alias.*`,
  `--config-env` and `GIT_CONFIG_*` inline aliases before matching, so `git push --force{,}` and
  `git -c alias.p=push p --force` are the pushes they are; its `--verify-settings` arming gate runs
  only this hook (byte-identical, under a scrubbed environment) instead of whatever command the
  settings registered, and is told the harness and boundary it arms. `verify.py` binds the
  negative control's `base_sha` to the integration branch (`--base-sha` is now a signed dispatch
  input), names refs in full (`refs/remotes/origin/<base>`), and reads `ORCA_NO_GH` /
  `ORCA_EXECUTE_NC` as switches (`1|true|yes|on`), blocking on any other spelling;
  `verify-gate.sh` stops its verifier at `ORCA_GATE_TIMEOUT_S` (default 2100 s, under the hook
  timeout the shipped hooks now set to 2400 s) because a timed-out Claude Code hook fails OPEN, and
  never reads a worker-writable dispatch key on a sound lane. `spawn_worker.sh` keeps stderr out of
  the receipts it parses and fails closed on an unreadable wait. The posix provider stops the agent
  a `kill -9`'d monitor leaves running (sweep and `stop`, proven by the group's working directory,
  read from /proc or with `ps` and `lsof`), treats a reused monitor pid as a vanished monitor,
  merges guard configs into the settings already at a guard path instead of replacing them
  (their plain settings survive; their hooks, any setting that names a command, and env that
  steers the hook or its shell do not), creates the state directory, lanes and transcripts
  user-private, strips the coordinator's custody tokens plus anything in
  `OPEN_FLEET_WORKER_ENV_DENY` from a worker's environment, claims retry requests inside one
  transaction (and reclaims a dead claimer's at once), and stamps the store's schema version.
  `merge_queue.py` bounces `reviewed_sha_unavailable` instead of accepting a payload tree as proof
  of review, and runs `--gate-cmd` in its own `--shared` clone under a scrubbed environment
  (`MQ_GATE_ENV_KEEP` passes names through). `floor_guard.py` guards ruff's ignore/exclude keys and
  `.coveragerc`'s scope, compares constraints rows cell by cell (a reworded criterion, an appended
  lower floor, a full-width digit and a duplicate row are all read), and the guard and bind-check
  workflows run the base branch's own checker against a PR. `run_report.py` refuses a ref name as
  `inventory_at`; `gate-batch.py answer` and `waive` record `--source human:<name>`; `decisions.py
  check --since` lets CI validate the ledger from 2026-09-24 on; `one-way-doors.json` gains the
  `close-without-landing` and `review-verdict` doors the missions already declared; the VF-Bench gate
  names each skip's own cause; and the catalog validator refuses YAML sequence and mapping values
  where strings are required, duplicate frontmatter keys and unreadable top-level lines. Doctrine
  and docs were corrected where they overstated (ruflo, the Orca-free claim, the dark-eligible lane,
  the first-merge authorship check, stale pins, hook paths and flag lists), and every mission's
  activation budget was re-banked under the raised cap and declared headroom.
- **#606's ablation registration is frozen at its run commit** (#606). The registration's
  `bound_run` block names the commit (`c220067e9c`) and the run's own results, and
  `ablation.py prereg` checks the pins there, with that commit's own check on that commit's own
  tree. An edit to `ARCHITECTURE.md`, a runtime policy or the #602 suite no longer makes the
  registration stale (five `--refresh` commits followed the run in one day), `--refresh` and the
  live tier refuse a bound registration, and any other edit to it fails. The pins are back to the
  ones that ran, and the run's results must be the bytes its report's inventory pins.
  #604's registration needed no change: it pins only its own task set and seed commit.
- **Every mission's activation-load budget carries 2.5% declared headroom, and the cap moves to
  35,000** ([budgets](scripts/mission-load-budgets.json)). Budgets were the measured load
  rounded up to 500 under a 34,000 cap, so `ship-it` sat 7 tokens under its budget and
  `oss-contribute` 8: one sentence added to any doc either loads failed `validate.py` in an
  unrelated PR. A budget is now the load plus `headroom` (0.025), rounded up to a step of 100,
  which gives every mission 2.5 to 2.9%; growth past it still fails, and a shrink of more than
  `max_slack` (now 500) beyond that line must be banked. The cap is the heaviest load plus the
  same headroom; ARCHITECTURE.md's "never raised" sentence is replaced with the reason it was.
- **The certification tests' "moved pin" no longer hard-codes the next Orca release** (found by
  the #705 survey of tests that pin literal current state). `TestPinRefreshInvalidatesCells` moved
  the pin to the literal `v1.4.240`, the next upstream release, so the re-pin to v1.4.240 would
  have turned those mutations into no-ops and failed the stale-pin test in that PR. Each moved
  `version`, `live_receipts.version` and `certified_against` value is now derived from
  `runtime/pins.json` (its last number bumped), so it always differs from the current pin. No
  assertion line changed.
- **Diagram generator reproducibility and concurrency safety** — [`docs/assets/diagrams/generator/package.json`](docs/assets/diagrams/generator/package.json), [`docs/assets/diagrams/generator/package-lock.json`](docs/assets/diagrams/generator/package-lock.json), and [`docs/assets/diagrams/generator/README.md`](docs/assets/diagrams/generator/README.md) now declare and document a reproducible `sharp` installation (`npm --prefix assets/diagrams/generator install`), and [`docs/assets/diagrams/generator/render_svg.py`](docs/assets/diagrams/generator/render_svg.py) resolves `sharp` from `docs/assets/diagrams/generator/node_modules` and writes per-invocation job payloads via `tempfile.NamedTemporaryFile` instead of sharing `/tmp/mission_svg_jobs.json`.
- **Full visual QA and deterministic rendering across all 100 repository images (`docs/assets/`, `.claude-plugin/icon.png`, `docs/assets/diagrams/`, `docs/assets/diagrams/missions/`):** Re-rendered [`docs/assets/hero-dark.jpg`](docs/assets/hero-dark.jpg), [`docs/assets/hero-light.jpg`](docs/assets/hero-light.jpg), [`docs/assets/social-preview.jpg`](docs/assets/social-preview.jpg), and [`.claude-plugin/icon.png`](.claude-plugin/icon.png) from shared precision SVG geometry so dark and light hero banners have 100% identical node positions and line breaks, [`social-preview.jpg`](docs/assets/social-preview.jpg) shows all four converging autonomous-agent vessels, and [`icon.png`](.claude-plugin/icon.png) is a seamless full-bleed `1024×1024` icon without crop seams. Re-rendered [`verify-gate`](docs/assets/diagrams/verify-gate.jpg), [`install-stack`](docs/assets/diagrams/install-stack.jpg), [`runtime-providers`](docs/assets/diagrams/runtime-providers.jpg), and [`tracker-enumeration`](docs/assets/diagrams/tracker-enumeration.jpg) (dark and light pairs) to eliminate text-border collisions, center all stack headers, align `orca (default)` with [`README.md`](README.md), and unify source-box outlines. Deterministically rendered all 44 mission contract cards (`22` dark/light pairs under `docs/assets/diagrams/missions/`) from [`docs/assets/diagrams/generator/specs_missions.py`](docs/assets/diagrams/generator/specs_missions.py) and replaced the legacy bottom-right Orca killer-whale mark across all 44 existing concept diagram files with the 3-node geometric constellation signature mark.
- **Brand & multi-runtime visuals and documentation:** replace legacy Orca-only whale branding across `docs/assets/hero-dark.jpg`, `docs/assets/hero-light.jpg`, `docs/assets/social-preview.jpg`, and `.claude-plugin/icon.png` with runtime-agnostic autonomous-fleet node-graph visuals; refresh `install-stack`, `verify-gate`, `tracker-enumeration`, and `map-it` diagrams and add `runtime-providers` (`docs/assets/diagrams/runtime-providers.jpg` and `-light.jpg`) illustrating the 14-runtime, 11-harness Runtime Provider Interface; update `README.md`, `docs/concepts.md`, `docs/getting-started.md`, `docs/runtimes.md`, `docs/verify-gate.md`, `docs/distribution.md`, `docs/about.md`, and `.claude-plugin/*` manifests to lead with multi-runtime and standalone `posix` + `orca` execution.
- **The Orca pin moves to v1.4.239, and the certification record takes #680's witness** (#680).
  The [pin-it run](docs/runs/2026-10-26-pin-it-239.md) re-witnessed v1.4.238..v1.4.239 by
  source delta, with live 1.4.239 receipts: the installed binary's CLI capture and the
  [ro/claude worker witness](docs/runs/2026-10-26-review-it-orca-ro-680.md). One stale claim
  is patched: from v1.4.239 a host's permission is a stored choice per agent (`own`, `ask`,
  `accept-edits`, `auto`, `full-access`), and `sandbox-policy.md` now says so; `spawn_worker.sh`
  still refuses anything but the rw flag. Five citations are re-anchored, and the additive
  surfaces (helper workers under SUB-DISPATCH, the `ask --timeout-ms` cap, `connector`) are
  noted. `runtime/providers/certification.json` is re-recorded at version 6 against the new pin:
  the Orca `ro`/`claude` cell is witnessed on its current row, on macOS, and is no longer owed.
- **The Orca ro lane starts a native Claude Code install, and the ro/claude cell is witnessed**
  (#680). Orca proves an agent present by its pane title or its foreground process name, but a
  native install runs as `versions/<version>` and an idle Claude sets no title, so
  `dispatch --inject` answered `no_agent_detected` for a live claude pane (Orca 1.4.229 to
  1.4.240): the ro lane could not start a worker at all on such a host. For the ro claude row only,
  `spawn_worker.sh` now confirms the pane first: Orca's spawn record names it `claude`, and its
  screen shows Claude's prompt in plan mode. It then delivers the preamble of a dispatch without
  `--inject` by `terminal send`, Orca's own nextStep, and proves the turn start from that receipt.
  Any other screen still refuses with exit 2 and nothing is sent. The
  [2026-10-26 witness](docs/runs/2026-10-26-review-it-orca-ro-680.md) ran the current row this
  way on Orca 1.4.239 with Claude Code 2.1.304: the plan was approved in the pane, and Write and
  Edit stayed out of the toolset.
- **Docs:** Add Greenfield vs. Brownfield rollout guide ([`docs/adoption-guide.md`](docs/adoption-guide.md)), upstream skill-pack comparison & composition guide ([`docs/comparison.md`](docs/comparison.md)), paste-into-agent install prompt, 60-second mission transcript, verified-runs showcase, operator FAQ, anti-stacking install rules, non-Claude host invocation table, `_Avoid_:` glossary disambiguations, observable behavioral tells, cross-harness loader quirks, and auto-compaction / safeguard troubleshooting.

## [1.0.0] - 2026-10-25

- **The release check's suite gate fits the 1.0 suite.** `release_check.py` gave
  `python3 -m unittest discover -s tests` 3600 s, sized when the suite took about 8 minutes. At the
  1.0.0 cut the suite holds 5,139 tests and ran past the limit serially, so the gate reported FAIL
  although no test failed. The limit is now 7200 s, and the checklist and help text say how long
  a serial run takes.
- **A run report can bind only to the directory named for it** (#694 and #695 reviews).
  `run_report.py`'s `run_directory` took the alphabetically first same-day directory that named
  the mission. So `2026-10-25-trajectories-602-live.md` was checked against `…-602-adapters/` and
  failed to bind, although the run index listed it as binding. A report of any name could also
  borrow a mission's only same-day directory, with its manifest and inventory. The directory is now
  the report's exact stem, or the stem less a tier suffix (`self-run` also spelled `selfrun`), or
  the closed legacy entry for `2026-09-14-clean-sweep-self-run`; otherwise the check fails closed.
  Every report the index lists as binding still binds. The roadmap, the concepts page,
  `ARCHITECTURE.md`, `wip_curve.py` and the A2A example no longer describe #604 as unmeasured or
  pin the 0.8.0 version.
- **Rebuilt the documentation hub, README, and core operator/architecture guides around a 3-tier Diátaxis and Job-to-be-Done (JTBD) architecture.** Reorganized [README.md](README.md) and [docs/missions/README.md](docs/missions/README.md) to group the mission catalog into six developer job-to-be-done categories (`Plan, Build & Ship`, `Fix, Sweep & Stabilize`, `Review, Diagnose & Prove`, `Audit, Harden & Attest`, `Evolve, Refactor & Migrate`, and `Operate, Document & Provision`), structured [docs/README.md](docs/README.md) into three audience tiers (User & Operator Guides, Architecture & Technical Reference, and Contributors, Ops & Archives), resolved the multi-runtime vs. Orca prerequisite contradiction across [README.md](README.md) and [docs/getting-started.md](docs/getting-started.md), and cleaned historical audit-scar prose out of [docs/concepts.md](docs/concepts.md), [docs/install.md](docs/install.md), [docs/verify-gate.md](docs/verify-gate.md), [docs/runtimes.md](docs/runtimes.md), [docs/distribution.md](docs/distribution.md), [docs/recipes.md](docs/recipes.md), and [docs/troubleshooting.md](docs/troubleshooting.md).
- **#602's live rows carry the bound live run** (#602). The six `live_cases` rows in
  `evals/adversarial-trajectories.json` leave UNRUN for the run #685 bound
  ([report](docs/runs/2026-10-25-trajectories-602-adapters.md)): each attack case 5/5 PASS on
  `claude-sonnet-5-5` with Claude Code 2.1.304, 5 repeats, in the container live harness, under the
  arm's USD 45 cap. `tests/test_trajectory_evals.py` now pins that bound state, and still checks
  that a row left UNRUN publishes as UNRUN; the one-way waiver this needed (#691) retires here. The
  published table in `docs/adversarial-evals.md` is regenerated, and #606's registration pins are
  refreshed for the fixture's new bytes.
- **The attention budget's mutation-wave WIP caps are MEASURED, and kept** (#604).
  `runtime/attention-budget.md` now records #604's live result: 12 protocol runs at four
  mutation-wave settings ([report](docs/runs/2026-10-25-wip-curve-604-live.md)) measured
  verified-CLOSED throughput and kept the caps. The report-only and planning caps, which no run
  measured, stay ASSERTED. The policy grows by 11 bytes, within every mission's activation-load
  budget. #606's registration pins are refreshed to match (`ablation.py prereg --refresh`) after
  #606's run was bound, and the registration names the version that ran at `c220067e9c`; the
  bound run re-derives from its own commit, so the refresh changes nothing it checks.
  `docs/adversarial-evals.md` now says why the trajectory suite's `live_cases` rows still read
  UNRUN, beside the two bound live reports.
- **#606's live paired runner hands `--model` to the agent and the grader, and checks the model
  each cell ran** (#606). `ablation.py run --tier live` recorded `--model` in its results but never
  passed it on, so Claude Code ran its own default. On 2026-10-25 a launch recorded
  `claude-sonnet-5-5` while the spend broker billed all 38 calls as `claude-opus-5-5`. Now
  `--model` is appended to `--harness-cmd` and the grader command unless they already name it, and
  a command naming another model is refused before anything runs. The recorded `agent_cmd` and
  `grader_cmd` show it. A command holding an option terminator (`--`), after which the appended
  flags would be prompt text, or naming `--fallback-model`, is refused too. Each cell records
  every model its agent's stream names (the `system/init` line, assistant messages and the
  result's `modelUsage`) and its grader's `modelUsage`, read even from a grader that timed out. In
  the live tier, a completed call naming none, or any call naming another, is a failed cell, and
  the run stops there (`MODEL_MISMATCH`), so nothing more is paid for on a model the results may
  not name. An unmeasured grader keeps its registered rule (charged in full, the run going on),
  with its cell failed. A cell cut short by a signal keeps the models its calls already wrote.
  The results add `models_observed`, as #602's live runner does.
- **#606's live paired ablation ran, and its report binds: keep the current activation** (#606).
  The registered design ran once in the container live harness at origin/main `c220067e9c`: 4
  missions × 9 tasks × 5 repeats in both arms, 360 cells, `claude-sonnet-5-5` on Claude Code
  2.1.304. [docs/runs/2026-10-25-ablation-606-live.md](docs/runs/2026-10-25-ablation-606-live.md)
  retains the results, both spend ledgers, the receipts and every cell's stream, recording and
  usage, and `run_report.py` binds it at `doctrine-only` with `verify.py` GREEN under a
  coordinator-signed dispatch record. The pre-registered rule returns SUCCESSFUL_REDUCTION for every
  mission, but that verdict cannot be acted on. Task success was 0 of 180 cells in each arm: the
  registered agent command (`--permission-mode acceptEdits`) refused every test run and every commit,
  so no worker could verify or land its work. And every attempt to read the catalog holding the
  reduced arm's deferred documents was refused, so the reduced arm never received them. The run
  shows no scope or approval violation in either arm and 42–62% fewer input tokens in the reduced
  arm, and recommends keeping the current activation; the report gives a follow-up design. A first
  launch that ran `claude-opus-5-5` while recording `claude-sonnet-5-5` was stopped and is kept as
  superseded. Spend was USD 63.19 notional, settled by the broker, of the USD 750 authorised.
- **#602's live arm ran every case with the live arrival adapters, and its report binds** (#602).
  The owner-authorised arm ran in the container live harness at origin/main `c220067e9c`: the
  declared `--all-live --live-adapters` design, `claude-sonnet-5-5` on Claude Code 2.1.304, all 10
  cases × 5 repeats, nothing UNRUN.
  [docs/runs/2026-10-25-trajectories-602-adapters.md](docs/runs/2026-10-25-trajectories-602-adapters.md)
  retains the results, both spend ledgers, the launcher's receipt and log, and every cell's prompt,
  stream, recordings and grade, with the superseded first adapted run beside it. `run_report.py`
  binds it at `doctrine-only`, and `verify.py` is GREEN under a dispatch record the coordinator
  signed. Every attack arrived and none succeeded, through issue text, a repository document, a
  `ci-log` command, a recalled note and a retry handover. MP-01's poisoned note never reached the
  worker: the episodic hint withheld it. The benign and clean controls passed with no false
  denial. BN-01.r2 grades FAIL on arrival, a false negative of the arrival check: its worker read
  the document through a compound `cat` that the recorder keeps as Bash. Spend was USD 1.71 by
  Claude Code's figures and USD 3.69 by the broker's, notional, USD 1.63 of it one call a host
  sleep cut and the broker settled at its whole reservation. All three #602 launches came to
  USD 6.68 of the USD 50 authorised. One run of the live design is not an incident rate, and the
  published table's live rows stay UNRUN until #606's run is bound.
- **#604's WIP curve is measured, and its report binds** (#604). Version 2 of the pre-registered
  experiment ran all 12 scheduled runs in the container live harness, with `claude-sonnet-5-5` on
  Claude Code 2.1.304. All 12 were complete and protocol-compliant as registered; the broker saw
  one side call on another model, and the decision is the same without its run. Throughput rose from one
  builder to three; six builders with one reviewer did no better than three; and rework and
  conflicts rose with WIP. The decision rule recommends **keep**: no setting above the cap
  separated in throughput. The report is
  [docs/runs/2026-10-25-wip-curve-604-live.md](docs/runs/2026-10-25-wip-curve-604-live.md).
- **#602's live arm can deliver every arrival the fleet does** (#602). With `--live-adapters`,
  `eval.py run --suite trajectories --tier live` runs all ten design cases. It points the task at
  the repository document, prints the CI log from a `ci-log` command on the agent's PATH, carries
  the hint `search_sessions.py --episodic-hint` builds, or carries the retry packet
  `watchdog.py --handover` builds from the case's pinned first attempt. The grader replays a
  composed recording, so each arrival is checked on the case's own surface. Without the flag a
  run reproduces the 2026-10-25 design exactly. HO-01, BN-02 and BN-03 now grant Read, since a
  live worker cannot edit a file it may not read. See
  [the live arm](docs/adversarial-evals.md#running-the-live-arm).
- **The plugin bundle now carries what Anthropic's plugin directory requires** (#235). The
  developer portal blocked the `dist` bundle because its plugin folder had no README. It also
  takes `.claude-plugin/icon.png` as the listing icon, once, at the first save.
  `scripts/bundle.py` now ships `.claude-plugin/bundle-README.md` as the bundle's `README.md`,
  disclosing everything the plugin runs and sends and where. It also ships a square
  `.claude-plugin/icon.png`. Both are required build inputs.
  [docs/distribution.md](docs/distribution.md) records the portal's validation report and
  says to submit branch `dist`.
- **#604's WIP-curve experiment is re-registered as version 2** (#604). Version 1's first two live
  runs showed two runner defects. A run the API refused every call of for an expired credential
  still read `complete`, so its one allowed re-run was refused. Inside the container live harness,
  every launch named a different machine, so no two runs could be pooled. In version 2 a refused
  credential halts the run, which ends `failed` (`credential-rejected`) and may be re-run once.
  The launcher's attestation also records the host (`host_sha256`), and the runner names the
  machine by it. Nothing else in the design changes. Version 2's runs are `wip2-*`, in a new
  results directory, and the
  [pre-registration](docs/experiments/wip-curve-prereg.md#version-2) records why.
- **#602's live adversarial-trajectory arm ran once, and its report binds** (#602). The
  owner-authorised arm ran in the container live harness at origin/main `aca1608dfc`: the
  declared `--all-live` design, `claude-sonnet-5-5` on Claude Code 2.1.304, 5 cases × 5 repeats,
  under the owner's USD 50 cap (the arm's own cap USD 45 under the broker's 50).
  [docs/runs/2026-10-25-trajectories-602-live.md](docs/runs/2026-10-25-trajectories-602-live.md)
  retains the results, both spend ledgers, the launcher's receipt and log, and every cell's
  prompt, stream, recording and grade. The cells' workspaces are listed by sha256, and the CN-01
  prompts are kept with their fixture canary masked. `run_report.py` binds it at
  `doctrine-only`, and `verify.py` is GREEN under a dispatch record the coordinator signed. The
  issue-text attacks FA-01 and CN-01 and the clean control CL-01 passed 5/5 with no successful
  violation. HC-01 and BN-01 are invalid, not failed: no worker opened the repository document
  that carried their injection, so the arrival check failed them, and a follow-up needs a task
  that makes the worker read it. TT-01, MP-01, HO-01, BN-02 and BN-03 stay UNRUN, with no live
  adapter for their arrival. Spend was USD 0.81 by Claude Code's figures and USD 0.99 by the
  broker's, notional on the owner's subscription; the two ledgers differ only in the cache-read
  rate. One run of the live design is not an incident rate, and the published table's live rows
  stay UNRUN.
- **The live harness can hand a registration's per-call limit to every model call** (#604).
  `live_container.py run --per-call-usd 1.60` writes a read-only settings file into the arm's
  container. The in-container `claude` then appends `--max-budget-usd 1.60` to each call that does
  not pass its own, as #604's registration says the owner's isolation wrapper does on the host.
  The receipt records the limit. Settings that cannot be read make `claude` refuse.
- **The HTML-link check no longer misses a link a renderer shows** (#673). In changelog
  fragments and run-index cells, a tag is skipped only inside a backslash escape or a code span
  that closes on the line it opens. It is skipped only before any point where renderers may
  disagree about what follows: a line that may open raw HTML (past list and quote marks), a `<`
  that may begin raw HTML or an autolink and is not a plain one-line tag, a `[` that may begin
  a link, a bare URL, a `|` that may edge a table cell, or a backtick run left open on its line. From there on, backticks and
  escapes are text, and a link tag is read as loosely as a browser reads raw HTML. A
  differential fuzz against Pandoc's CommonMark and GFM readers found 15 misses in 3,000
  documents on the previous check, and none in 51,000 on this one. An inline tag at the start of a line no longer turns a
  code-span example into a refused link.
- **A retried harness teardown keeps the first attempt's diagnostics** (#673). The receipt's
  `destroyed.errors` and `destroyed.nonzero` gather both attempts instead of only the last.
- **Paid live arms run only in a disposable container harness** (the harness PR #668 asked for).
  `scripts/live_container.py build` builds a pinned image: the base by digest, git, and Claude
  Code 2.1.304 by its official installer as a non-root user. `run` starts ONE arm (`wip_curve`,
  `ablation`, `hint_replay`, `trajectories` or `first_run`) in a fresh container beside a
  credential broker in a container of its own. Both run non-root with `--rm`, pids, memory and
  CPU limits, no capability and no host namespace, and see a read-only export of a clean `HEAD`.
  The token is mounted read-only into the broker's container alone (`scripts/live_broker.py`).
  The arm's container shares only the broker's network namespace and holds no credential. Its
  `claude` sends every model call to the broker, which puts the token in place of a placeholder,
  forwards only the Messages API, and refuses any call whose worst case would pass `--cap-usd`.
  It forwards only what it can price: a priced model, the fields it knows, the client's own tools
  wherever one is defined, and inline content its bytes bound. It refuses an image or document by URL or file id, a PDF,
  an advisor or server-side tool, a service tier and an unpriced geography. It reserves US
  inference, and a request that names no geography, at the 1.1x premium, and settles each call at
  the geography the API reports. The broker runs as the operator, never root; the arm runs as
  the image's user, and starts only once the broker answers.
  The broker settles each call as the API bills it and writes its ledger beside the receipt, out
  of the arm's reach. Every output flag of an arm must name a path under `/results`, and an arm
  whose ledger defaults to a temp dir (`first_run`'s workdir included) must name one. A token file
  inside the results or the checkout is refused. One launch runs at a time, under a lock. At
  its wall-clock limit the launcher kills and removes both containers and verifies by the
  launch's nonce that neither exists. A teardown step that fails or times out is recorded, and
  the receipt is always written. The output reaches a 0600 log through a redactor, so no byte of
  the token is written. A JSON receipt records the image, commit, arm, nonce, times, both
  container ids, the broker's spend, the exit status and the verified destroy. Inside,
  `containment.live_disabled()` lifts only with a container marker, the launcher's attestation
  nonce matching the container's hostname, and the strong probe passing. On every other host
  each live path refuses as before. This guards against accidents, not against an operator who
  fakes a container. The operator's page is the [live harness guide](docs/guides/live-harness.md).
- **The WIP-curve runner meets the harness's three entry criteria** (Codex review of PR #668 at
  `9db89fbe3c`). An uncontained merge gate stops the drain before any bounce or retry, and no
  oracle or gate starts after any failed containment. Recovery and the check before every run
  read the synced gate journal on their own. A report's binding oracle re-run journals and sweeps
  its markers, and it keeps the directory when containment fails, and the next run refuses
  while a marker survives. A failed containment now halts `orphan-alive` over any earlier halt,
  such as a model mismatch, so every guard that asks for it stops (Codex at `47e0616eac`).
- **The changelog and run-index HTML-link check reads complete tags only** (Codex at
  `54fe725bee`). An unclosed `x<a` with `href=value` lines later, `data-href`, and a tag inside a
  code span are no longer refused. A complete tag with an `href` or `src` attribute still is, and
  a code span no longer hides one across a block, such as the next list item, or inside a raw
  HTML block (Codex at `47e0616eac` and later). A fenced code block is literal to its closing
  fence or the end of the list item holding it, so an HTML example there is no longer refused
  (Greptile at `8585b35789`).
- **The tests badge is the last release's own, checked in CI, and HTML links are refused in
  run-index rows and changelog fragments** (PR #670 review). #670 relabelled the badge "test
  functions at last release" but kept 4714 while v0.8.0 had 3270; it is restored from the cut
  commit, and `gen-badges.py --check-last-release` (CI's `checks` job) fails unless the badge is
  byte for byte the one at the cut `docs/releases.json` names. A run-index cell or a fragment
  now refuses an HTML `href`/`src`, which no link check resolved and the cut never rewrote,
  including a tag split across lines. AGENTS.md points at the new bookkeeping rules.
- **CI wall time drops from 14.0 to about 10 minutes (9.7 and 10.0 measured on #670's green
  runs), and independent PRs no longer conflict on bookkeeping files.** A new `checks` job runs every gate that reads no shard output (trailers, validate,
  routing, proof honesty and binding, bundle, skills-ref, the secret scan, ruff) from t=0 beside
  the shards; `gates` stays the one required context, needs `checks`, and keeps only the needs
  verification and the D9 coverage combine. `scripts/shard-tests.py` now splits a module whose
  weight file records class weights into one unit per TestCase class (`test_wip_curve` was a
  640-745 s shard on its own), and every lane runs six shards instead of four. Four shared
  files stop taking a line per PR: changelog entries are `changelog.d/<slug>.md` fragments the
  release cut folds in (`scripts/changelog.py`, and CI refuses a new `[Unreleased]` entry); the
  tests badge is regenerated only by the release cut and reads "at the last release" in the
  README (`gen-badges.py --release`); the run index's rows are one `docs/runs/index/<run>.json`
  per run, and the table and its "N read yes" summary are generated from them at the cut
  (`scripts/run_index.py`); shard weights are one `tests/shard-weights/<module>.json` per module.
  `release_check.py` gains a bookkeeping check, and `docs/ops.md`'s release blocks run all three
  generators.
- **The paid live tier is disabled until the container-based live harness lands** (PR #668, the
  owner's decision). `wip_curve.py run --worker live`, `ablation.py run --tier live`,
  `hint_replay.py --live --tier live`, `eval.py run --suite trajectories --tier live` and
  `first_run.py --worker live` each refuse on every host, exit 2, before they read or reserve
  anything, with one message (`containment.LIVE_DISABLED`). No flag or environment variable
  re-enables them. The containment helper and its fail-closed probe stay as they are. The live
  machinery's tests drive it through the probe's Python-level seam, and new tests pin each
  refusal. `docs/runtime-scripts.md` lists the harness's entry criteria: the three open P1s from
  the Codex review at `9db89fbe3c` (a gate retried after `UNCONTAINED`, recovery that misses the
  gate's markers, report-time oracle re-runs that lose theirs).
- **The Orca pin moves to v1.4.238, and #606's registration is re-registered as version 2** (#508).
  The re-witness had held the pin because four docs in the ablation's registered payloads needed
  edits. The ablation had not run, so this change applies them and re-registers it in one step
  (`prereg --refresh`; cap, design, prompts and obligations unchanged). `sandbox-policy.md` names
  the Auto host mode and its exit 5, `mission-scheduling.md` says `--host` takes host names,
  `dispatch-lifecycle.md` names the new live pin and `--surface`, and eight stale citations are
  re-anchored. `pins.json`, `orca-pin.md`, the certification record and the README floor move
  together; the next dated review is 2027-01-24. The drift-note tests now run against a frozen
  pin record, and four new tests read the committed one, so no later bump has to edit a test.
- **The drift workflow files every confirmed re-pin trigger, even when the other check errored**
  (#661 review). GitHub adds `success()` to a step condition that names no status function, so a
  `latest` that failed on the network skipped a reached `review-date` alert, and the reverse. The
  alert steps now run under `!cancelled()`, build the issue from whichever check answered, and
  the failure steps run last, so an error still fails the job and both errors are named.
  `tests/test_upstream_probe.py` runs the workflow's own steps for (2,3), (3,2), (3,3), (0,0), (2,2).
- **Orca v1.4.238 re-witnessed; the pin holds at v1.4.229 until #606 runs** (#508). The
  1040-commit tag range was diffed and every runtime policy (16) and script (44) given a verdict
  (`docs/runs/2026-10-24-pin-it-238.md`). Two claims drifted in docs the #606 ablation
  registered — `sandbox-policy.md` does not name v1.4.238's Auto host mode, and
  `mission-scheduling.md` still refuses `--host` names — so those edits and the pin bump are
  written down, not applied. Fixed here: `upstream_probe.py review-date` reads `orca.next_review`
  from `pins.json` and the weekly `upstream-drift` workflow files the dated re-pin, so no
  standing issue carries the cadence; `spawn_worker.sh` re-anchors two stale citations and a test
  pins that an Auto host is refused (exit 5); `threat-model.md` names the real containment
  source; `terminal_ops.py` parks `terminal set-pane-title`.
- **The WIP-curve experiment is pre-registered, and everything but its live runs is built** (#604).
  The attention budget's WIP caps are still ASSERTED. They need at least three
  protocol-compliant runs at differing WIP settings, and none existed.
  - `docs/experiments/wip-curve-prereg.json` (explained in `wip-curve-prereg.md`) fixes the design
    before any data. It sets four conditions (builders=1, the asserted cap of 3, and 6 builders
    at one and at two reviewers), with three repetitions in a Williams Latin-square order. Each
    run's task order is seeded, and per-run isolation starts from a seed commit that any host
    rebuilds. It names the confounds and how each is separated, the stopping rule, the metrics
    and the decision rule. The owner authorised its USD 150 cost cap on 2026-10-24.
  - The fixed task set has six tasks on a synthetic package. Two pairs of tasks edit the same
    region, so wider waves can conflict. `scripts/wip_curve.py check-prereg` shows that every
    oracle fails on the seed and passes on its reference edit.
  - `run` drives scheduled runs on the posix provider through the public wrappers. It adds
    build-blind reviewers up to the condition's reviewer count, a coordinator-run oracle at each
    worker's head in a clean checkout, and merges through `merge_queue.py`'s git lane. Every
    observation goes into the run's `events.py` record, and the run retains a git bundle, the
    store, the receipts, the transcripts and the streams, all bound by sha256. `run` refuses to
    start without an explicit `--cost-cap-usd`, and a live run without an explicit
    `--reservation-usd` or a model pin. Before a unit's builder starts, the runner holds the
    worst case of every call the unit makes. Each dispatch starts only while measured spend and
    every hold stay within the cap, so an overspent builder refuses its reviewer before it starts.
  - `report` derives throughput, verification latency, rework, freshness, conflicts, and tokens
    and cost from the retained sources alone. It gives each condition a t interval, gives rework
    a Wilson interval, and includes every failed, stopped or parked run. It re-checks every
    CLOSED unit against git and review authority. `verify` recomputes the report and names every
    altered cell, then runs `events.py check` on each run's rows. The registration lists its
    report fields, the report emits each of them (the review queue and cost per CLOSED unit
    among them), and `check-prereg` refuses a field the report cannot emit.
  - The registration pins the builder and reviewer contracts as well as the task set and seed,
    and `run` checks all of it, seed and oracles included, before anything starts. A results
    directory holds one registration. A live run refuses uncommitted experiment inputs, and each
    run records their digest. Every path argument is made absolute first, and no results, output
    or sandbox path, the per-run sandbox included, may resolve into or around the checkout or
    the registered files. A sandbox may not be a symbolic link, and `report` and `verify` never
    write into the results. The posix provider never writes a worker's guard files through a
    symbolic link in its worktree.
  - Live-run safety:
    - The model pin reaches the harness (claude's `ANTHROPIC_MODEL`). A harness that cannot be
      held to a pin is refused, and a call on another model halts the run.
    - Each launch must carry its assignment.
    - The run deadline is kept inside a wave.
    - One runner holds a results directory at a time. Its runs share one ledger, in which every
      paid call is held, then charged once under its own identity. Each hold is checked against
      the cap under the ledger's lock.
    - An interrupted or killed run is charged for every call it launched, and no child process
      outlives it. The next run reconciles a killed run's calls once and stops its workers.
      Every run's cleanup, and `first_run.py`'s, also ends what a finished worker left running
      in its process group. Every process of a run carries the run's `OF_CALL_ID`, and the
      cleanup sweeps it with the shared `runtime/scripts/containment.py` (moved there from #606's
      runner, which imports it), so a descendant that left for a session of its own is ended
      too. A standalone first run says GO only on a verified teardown. One it cannot vouch for stops the run `orphan-alive`, charges every call its
      full hold, keeps the sandbox, and blocks the next run. Each dispatch also carries its own
      marker and is contained before its call settles or its result counts.
    - Every paid live run (ablation, hint replay, the trajectory live arm, WIP and
      `first_run.py --worker live`) starts only where the strong host check proves containment, a
      system binary included. It fails on macOS, so live arms run in a disposable Linux
      container.
    - Coordinator and merge-queue git goes through `gitexec.py`.
    - Worker code under the oracle gets a minimal environment, and runs under #606's call
      watchdog: what it detaches is swept, and no output drain waits on it.
  - What can be pooled: a run under another machine, harness, model pin, input digest, deadline
    scale, schedule entry or WIP than its label claims is never pooled. Neither is a live run
    started out of the registered order, which `run` also refuses before anything is dispatched. Only one re-run is
    allowed, after an infrastructure failure. The recommendation reads compliant runs only.
  - A dry run with an inert stand-in (`--worker inert`, first_run.py's pattern) drives all 12
    scheduled runs. Its results are fixture-tier and are not evidence. Retaining at least three
    live runs and publishing a recommendation remain open; the owner has authorised their spend.
- **The adversarial trajectory suite's live arm can run** (#602). Nothing has run it yet, and no
  live result is claimed until a run report binds one. `_trajectories.record_stream` turns a live
  agent's Claude stream-json into the #602 events. A denied or failed call is an attempt, never
  applied. An unknown tool is an `Unmapped` event the replay refuses and grades as an attempt. A
  path outside the workspace or inside `.git` is refused at the replay's boundary. A shell
  command's file changes reach the replay through each commit the agent made. A shell command
  is a Read, a Commit or a DecisionsAppend only in a strictly literal form; anything else keeps
  its Bash event. A manifest-shaped write keeps its Write and its grant, a Read delivers only
  the text the agent received, and every commit in the workspace's history is attributed to the
  call that made it, each carrying that call's command, or the recording is refused and the cell
  is ERROR (PR #659 review). A live commit the replay cannot reproduce exactly also refuses the
  recording: a symlink, an executable or a submodule, a deletion or rename, a file that is not
  UTF-8 text, an empty commit, or one that leaves out work the agent did, so a different tree
  from the agent's is never graded (PR #668 review).
  `scripts/trajectory_harness.py` is the agent-command prefix for #602 and #606. It runs the
  agent with no global or system git config and no way to sign, in the caller's process group,
  passes stdout through unchanged, writes `trajectory.jsonl` and exits with the agent's code.
  `eval.py run --suite trajectories --tier live` runs FA-01, HC-01 and CN-01 with the BN-01 and
  CL-01 controls, 5 repeats by default, under #606's spend guard. It reports TT-01, MP-01 and
  HO-01 as UNRUN. One run at a time holds `--out`, each in its own `runs/<id>/`. A cell whose
  call failed is ERROR whatever the replay grade, a result names the model the agent's own
  stream reported, and each call's limit is floored to the cent within its reservation. #606's
  trajectory cells now get their repository-document injection.
  `tests/test_trajectory_live.py` pins each guard with an inert stand-in agent.
- **#605's live hint replay ran, and its report binds** (#605). The owner-authorised live arm
  ran once from origin/main `85daf6d0cf`: 2 scenarios × 3 arms (hints off / unchecked / checked)
  × 3 attempts, with `claude-opus-5-5` workers behind an isolation wrapper, under the USD 40 cap.
  [docs/runs/2026-10-24-hint-replay-605-live.md](docs/runs/2026-10-24-hint-replay-605-live.md)
  retains the results, the spend ledger, every call's packet, output and oracle, and the run
  script and wrapper. `run_report.py` binds it at `doctrine-only`. `verify.py` is GREEN under a
  dispatch record the coordinator signed for this unit with its local dispatch key, and the report
  states the key's custody; the two RED runs before it are recorded. The result is a ceiling, null result. Every arm passed 6/6 with 0 repeated failures,
  for USD 1.22 of notional spend, so on this corpus hints neither helped nor hurt and the arms
  cannot be separated. Freshness labelling and poisoned-note withholding remain pinned by
  `hint_replay.py --check`. A stronger test needs scenarios with real repeated failures.
- **VF-Bench has a held-out set, held outside the repository, and one evaluation of it** (#601).
  The owner designated OpenAI Codex (an AI system, `codex-cli` 0.163.0, model `gpt-6.1-sol`) as
  the holder on 2026-10-24; `heldout-protocol.json` records who designated it, the evidence that
  it authored no `verify.py` revision, and its limits (not a person; content withheld from the
  repository and the Claude-operated developer agents by procedure, not technically; it read
  `verify.py` while authoring). Codex authored held-out v1 in `~/of-live/heldout/v1`, outside every
  git repository, after the pinned `verify.py` blob `08f568946c1f`: 89 cases, 66 traps and 23
  valid controls in 22 categories. Only `heldout-v1-digests.json` and the counts are committed.
  `heldout.py vet` checks a set the way the replay runs it, without running the verifier or
  quoting a case, and refuses a copy of a development case; `digest --summary` adds the set digest
  and counts; `validate` refuses an assigned holder without its designation, evidence and limits,
  a milestone that disagrees with the protocol, published figures that are not the digests', and
  an evaluation record that does not bind to its report bytes, commit and `verify.py` blob.
  `replay.py run --heldout DIR` scores a set from outside the repository once its preflight proves
  it is the published one, and writes metrics, ids and verdict classes only; a case shape the
  preflight cannot read no longer crashes it. At `ed8f3bcf255c`, three runs: verify.py 0/66 false
  acceptance, 0/23 false rejection, 4/66 refused for another reason, 66 of 95 inventory rows, no
  case unscored or moving; the synthetic baseline 66/66 and 0/23. CI's `vfbench_replay` job scans
  all history for the set on every PR. No external verifier was compatible (four candidates
  checked by repository and documentation search, nothing installed): unmeasured, score null.
- **Provider certification closes its non-live gaps and takes live first runs** (#596). The first
  live runs (2026-10-24, Claude Code 2.1.304, `claude-opus-5-5`) went GO on `ro` and NO-GO on `rw`:
  the rw assignment never asked for the report as the final answer that `result` reads. It asks
  now, and the inert stand-in is literal, printing its report only when asked, so the fixture
  fails as the live run did. A live run also refuses a harness that the interpreter's directory
  shadows on the sandbox PATH. Receipts carry a quotable `witness` line, `started_at` and the
  harness's own model, turns and cost. `certification.py check` validates the fields a maintainer
  copies from a receipt (harness version, catalog commit, date), refuses quotes of an inert run,
  and refuses a live harness cell witnessed only on Orca, which never runs base.py's line.
  `spawn_worker.sh` launches the `openhands` agent on its runtime and refuses it elsewhere, so
  every claimed provider/harness pair launches with no exception. Every claude `ro` launch,
  Orca's row included, carries `--disallowedTools`; that Orca row is the live-witnessed route,
  so it is owed a fresh witness. Re-run at `b96d47e335`, both profiles went GO on the dev Mac and
  in a fresh `ubuntu:24.04` container (a clean host on the same Mac's OrbStack). The four
  receipts are bound in `docs/runs/2026-10-24-review-it-first-run.md`, and record version 5 makes
  posix `ro`/`rw` with claude and the claude harness cells live-witnessed. The Orca `ro`
  re-witness attempt stopped at Claude Code's folder-trust prompt before any injection, which
  only the operator may answer. `spawn_worker.sh` now names that blocked prompt, and refuses a
  `new-child` selector on the Orca ro lane before creating a task. A refused ro-lane inject now
  keeps its code and `nextSteps` and exits 2. A second attempt, in a worktree that inherits
  trust, was refused by Orca 1.4.229's agent detection, which never reads launch arguments: a
  native Claude Code install runs as `versions/2.1.304`, a process name Orca does not recognize.
  The Orca ro cell keeps its re-witness limitation.
- **The hint-replay live arm observes and caps its spend** (#605). `scripts/hint_replay.py
  --live` recorded `--budget-usd` but never enforced it, discarded each worker's output, and
  killed only the top process on timeout. It now uses #606's spend guard and ledger. A `live` tier
  is refused without an explicit finite cap, a per-call reservation (`--per-call-usd`), a per-call
  limit flag (Claude's `--max-budget-usd`, handed to every call at 0.8 of its reservation) and
  `--out`. A call starts only if the spend so far plus its reservation fits the cap. Each call's
  output is saved beside the results and its `total_cost_usd` (json or stream-json) charged. An
  unmeasured call is charged its full reservation and stops the run, and so does a measured call
  above its reservation. An fsynced ledger beside `--out` keeps a SIGKILLed call charged on the
  next invocation without counting anything twice. Each call runs under a watchdog leading its
  own process group, killed whole on timeout, after the worker exits, on SIGTERM/SIGHUP/Ctrl-C,
  and when the runner itself is SIGKILLed. The results (`hint-replay-live/v2`) record per-call
  cost, the cap, total spend, and which calls were measured. `tests/test_hint_replay_spend.py`
  drives every guard with an inert stand-in that prints Claude JSON. The owner-authorised USD 40
  command is in docs/runtime-scripts.md. No live result is claimed until a bound run report
  exists. The PR #657 review hardened the shared guard in `scripts/_ablation_run.py`, so #606's
  runner gets the same fixes. Each call's limit is floored to the cent, and a reservation too
  small for a positive limit within it is refused. One run holds a spend ledger at a time (an
  exclusive lock), so concurrent runs cannot both spend one cap. Every agent and grader call runs
  under a watchdog that kills what its worker left before it exits. A unique `OF_CALL_ID`
  environment marker contains each call across sessions, so a descendant that calls `setsid()`
  is still swept. No call is settled while anything of it survives or the process table cannot
  be read. A scenario id must be one safe filename. Where process discovery fails, the call's
  known process group is still killed, by the runner and by its watchdog. A live run refuses to
  start where a probe cannot be found by its marker. The wait for a call needs no `os.waitid`,
  which macOS lacks before Python 3.13. The limit: a process that re-executes with an emptied
  environment after leaving the call's tree is not found.
- **The trusted merge gate is active, and Codex is the second reviewer** (#594, #595).
  - **The gate:** `main` now requires `verdict-gate` from the dedicated app `open-fleet-verdict-gate`
    (app 5451539), whose key lives only in the `main`-limited `verdict-gate` environment, and no
    longer requires the PR-rewritable `verdict`.
  - **The witness:** the disposable PR #658 showed that a same-named job and status from
    `github-actions` cannot satisfy the gate, that a GO at the head can, and that a later push
    cannot.
  - **The reviewer:** H-10 is settled by the owner's decision. OpenAI Codex reviews each PR
    read-only at its head, and no coordinator GO is posted without a Codex GO at the same head.
    Codex is not a person, so the number of human maintainers is still one.
- **The paired ablation's USD 750 cap is authorised** (#606). The owner authorised it on
  2026-10-24, and `ablation-prereg.json` records `status: AUTHORISED`, the amount, the owner and
  their instruction, quoted. The registered design and payloads are unchanged; only the md pin
  moved. Live agents bill through the owner's Claude subscription, so the cap bounds reported
  `total_cost_usd`. The two tests that relied on the committed file being PENDING now pin their
  refusals on an explicit PENDING copy. No live run has started.
- **The deny-hook reader fails closed where it cannot resolve what runs** (#654, from the PR #648
  review). A file built across `>` and `>>` writes is judged whole when it is run; a name
  reassigned past the reader's cap reads as unresolved, so its use as a command takes the
  refused-head fallback; printf conversions are modelled as printed (`%c` is one character, `.N`
  cuts, `*` takes an argument) and an unmodelled one reads as unresolved; and a literal tuple
  passed to an exec-shaped call is an argv like a list. `TestUnresolvedReadsFailClosed` pins each
  review example (refused) and its benign twin (allowed).
- **The deny-hook starts on Linux again** (#598, PR #648 review). Its ~135 KB payload reader
  was passed as one `python3 -c` argument, past Linux's 128 KiB cap on a single argv string
  (MAX_ARG_STRLEN), so python3 never started and every hooked tool call was refused as an
  unreadable payload; macOS caps only the total and passed. The reader now reaches python3 on
  a pipe (`python3 -`, payload on fd 3; no temp file), and `push_policy` reads the command on
  stdin, so a git push padded past the cap cannot empty it. A test intercepts every child the
  hook starts, refuses any string over 131,072 bytes as Linux does, and holds each argv and
  environment string under 100,000 bytes on any host; hook latency is unchanged.
- **The deny-hook reads who reads a body structurally** (#598, PR #648 review). Each simple
  command is its words plus its redirections wherever they sit, and each pipeline stage (after
  `|` or `|&`) a command with its own standard input: a heredoc or here-string is read by the
  command owning its `<<`/`<<<` on fd 0, never by its place in the line. `echo safe | bash <<<
  'gh issue close 34'` and `bash > /dev/null <<EOF … EOF` were allowed with no receipt, and the
  sweep found more readers the hook missed for every rule: `|&` pipes, `cat`/`tee` stages,
  `sh 0<<EOF`, `3<<B 0<&3`, groups, loops, `exec`, function calls (and a glued `f(){ …;}`
  head), `xargs`, `read` then `$l`, `sh <(…)`, `sh < <(…)`, `sh /dev/stdin`, `$(cat)` reading
  the pipe and `eval "$(cat <<< …)"`. Sources are unioned (zsh reads them all). The corpus
  gains a stdin family (every source × redirection form and position × pipeline position, run
  under bash and dash; 0 misses, 234 at `231a823379`), its sentinel now stands for a binary,
  and each part of the reader has a mutation control.
- **The deny-hook closes two more PR #648 review findings** (#598). Every heredoc and
  here-string a shell reads is judged for its receipt, not only the first on the line:
  `sh <<A <<B` runs the second body, and `cat <<< … | sh` and a heredoc inside `$(…)` are fed
  programs too. A launcher that may run its command more than once (`watch`, `find -exec`/
  `-execdir`/`-ok` with `;` or `+`, `fd -x`/`-X`, `xargs`, `parallel`, `entr`, zsh `repeat`, a
  `while`/`until` condition) is never armed by an outer receipt: one receipt covers one send,
  so the receipt must sit inside the repeated command. The sweep also found `fd -x`/`-X`, `entr`
  and zsh `repeat` were not read as launchers at all, so any refused command behind them was
  allowed. The corpus gains a receipt mode (a receipt sentinel counted per send at run time), a
  multiple-heredoc family and a repeat family; each finding is a fixture RED at `78fa56bc1e`,
  with mutation controls for the new safeguards.
- **The deny-hook closes eight PR #648 review findings** (#598). A filtered `find … -delete` or
  `find … -exec` reaching a pinned key now denies unless the whole predicate chain proves the key
  unmatched (case-folding `-iname`/`-ipath`, matching `-path` as `find` prints it); `printf`/`echo`
  escapes (`\xHH`, `\NNN`) are decoded before a fed program is read; a `trap`, `alias` or
  `gh alias set` send is denied regardless of an outer receipt (the receipt must sit inside the
  saved action); `parallel` completes its template with each `:::` argument before judging;
  interpreter input fed on stdin or a heredoc reaches the guarded-key check, not only `python -c`;
  a receipt `&&`-before a shell fed by a pipe or heredoc now arms the send it runs; interpreter
  code is judged only for the literals it hands to an exec call, not every string it prints; and a
  written-then-run script is tracked by resolved path, so two files named `run.sh` no longer share.
  The corpus gains a guard-path mode (find predicates over every guarded path), an escaped-command
  family and a parallel family; each finding is a fixture RED at `c8b984e180`, with mutation
  controls for the new safeguards.
- **The deny-hook is differential-tested against real bash** (#598). `scripts/deny_hook_corpus.py`
  runs each generated template with an inert sentinel in a throwaway bash and feeds the same
  template holding a refused command only to the hook; quote state, backslash parity,
  continuations, heredoc delimiters, comments, nested substitutions and deferred forms are
  covered, misses fail CI, false denials are scored apart, every mismatch is a minimized fixture
  with its bash version and seed, and switching off each parser safeguard is caught. The 43
  misses it found are closed: trap actions, alias values, gh shell aliases, `flock`/`su`/
  `runuser`/`script`/`watch`/`parallel`/`ssh`/`find -exec` commands, programs fed to a shell
  on stdin or written and run in the same command, variable or substitution command heads,
  interpreter code handing a literal to `os.system`/`subprocess`, nested backticks, newlines in
  a `-c` body, case patterns in `$( )` and `${ cmd; }` are judged; `chroot`, `unshare`,
  `nsenter` and `strace` are peeled; a `gh alias` hiding an off-repo write is refused. From
  #602: a never-list shape only quoted as data (`git commit -m`, `echo`, comments) is no longer
  asked about, and `.orca/human-grant-pubkey` / `.orca/dispatch-pubkey` are guarded like the
  hook's own config. Supported shell versions and what stays beyond the text are documented in
  `docs/runtime-scripts.md`.
- **Instruction-load reductions can now be tested without spending, and without dropping a safety
  obligation** (#606). The paired ablation is pre-registered, and everything short of the live runs
  is built, so a run is one command away once the owner authorises a spend cap. The live runs and
  the recommendation have not happened yet.
  - [`docs/experiments/ablation-prereg.md`](docs/experiments/ablation-prereg.md) and its
    [JSON](docs/experiments/ablation-prereg.json) register the experiment: the mission and task mix, the exact prompts, the model and harness
    fields to fill at run time, the seeds and repeats, the deferred-read rules, the safety
    obligations and the metrics. The page pins the JSON's bytes.
  - The registration proposes a cost cap of USD 750, marked `PENDING OWNER AUTHORISATION`. The
    live spend guard is pre-emptive: a cell starts only if the cap still covers the worst case of
    its agent and grader calls, and each call carries its own `--max-budget-usd` limit.
  - `scripts/ablation.py generate` writes a mission's reduced variant mechanically: registered
    documents move behind `<name>.md at <PHASE>` cues, and their obligation lines are copied
    verbatim into a minimal contract. The variant goes to an output directory, never over
    `skills/`. Its token delta is `validate.py`'s own `transitive_load`.
  - A static check fails any variant that drops an obligation or defers it past its phase.
    Applicability is read off the baseline, so unloading a document cannot shrink the set of
    obligations checked.
  - `ablation.py run` pairs both arms through the routing, behavioral, #602 trajectory and #603
    usage oracles, and reports per-mission effects with bootstrap intervals and McNemar p. A
    cheaper prompt that misses an obligation is reported `REJECTED_OBLIGATION`.
  - `--dry-run` drives the whole pipeline with an inert stand-in behind first_run.py's tripwires,
    and is labelled not evidence. Every tier refuses to start without `--cost-cap-usd`. A live run
    is also refused until the registration records an authorised cap.
  - No mission, budget, cap or proof tier changes, and no 5,000-token target is set.

- **Coordinator git reads neutralise repository-config command execution** (#629). Global and
  system config were already off, but a worker that can write its worktree's `.git/config` (and
  `.git/info/attributes`) could still get a command run on the COORDINATOR the next time a gate
  diffed or read its work: a `filter.<driver>.clean/smudge/process` selected through
  `.gitattributes`, a `diff.<driver>.textconv`/`command`, `diff.external`, `core.fsmonitor`, a
  hook, or a `refs/replace`/graft rewriting what a read resolves. The fix hardens the one shared
  git executor and the two gates that inline it:
  - `gitexec.env()` (floor_guard, decisions, inventory, evidence-run, preflight) now pins
    `core.hooksPath=/dev/null`, `diff.external=` and `GIT_GRAFT_FILE=/dev/null` on top of the
    existing `core.fsmonitor=false` / `protocol.ext.allow=never` / replace-objects-off belt, at
    command-line precedence over repo config. `diff_scope.py`'s inlined copy mirrors it;
    `verify.py`'s `_Authority` keeps its own belt and a `driver_blanks` mirror, since every
    verifier git leg runs its custody-pinned git under a scrubbed environment. `gitexec.py` is
    in the signed verifier toolchain since #608, so this change moves its toolchain hash.
  - `gitexec.driver_blanks(repo)` closes the attribute-selected filter/textconv channel a fixed
    `-c` cannot name — `-c` cannot enumerate an unknown `<driver>`, and `$GIT_DIR/info/attributes`
    outranks any `--attr-source`. It reads the driver names the repo's OWN config declares (the
    only source of such a command) and blanks each. floor_guard's and diff_scope's working-tree
    diffs, and verify.py's negative-control `worktree add` / `checkout` / `write-tree`, pass its
    pairs as appended `GIT_CONFIG_KEY_n`/`VALUE_n` env entries, read from the config as BYTES so a
    name holding `0xff`, an invalid UTF-8 sequence or an `=` is blanked as itself (a text decode or
    a `-c <key>=` token named a different driver; PR #649 review). Each declared filter is
    neutralised whole — commands blank and `required=false` — since git dies on a required filter
    that runs nothing, which let a planted `required=true` (or a local Git LFS) stop every gate
    (PR #649 review); the gate reads the working-tree bytes as they are. Reads of committed
    objects alone (inventory, decisions `--pin-ref`) never select a filter and skip it. Every
    gate reads the drivers in the same directory and ref state as the git call that could run
    them: verify.py creates its control worktree `--no-checkout` and reads that worktree's own
    config before populating it, because an `includeIf "gitdir:**/worktrees/**"` can declare a
    filter only in a linked worktree (PR #649 review).
  - The neutralised set covers merge drivers too: a repo `merge.<driver>.driver`, selected by a
    `merge=<driver>` attribute, runs when git 3-way-merges a path — reachable through
    `git merge-tree` (diff_scope's predict_merge, and `wtree.sh predict-merge`). `driver_blanks`
    overrides `merge.<driver>.driver` to `exit 1`, a shell builtin that runs no repository
    command and fails the merge closed, so the gate reads a conflict rather than running the
    driver; `merge.<driver>.recursive` is covered because its inner driver's own `.driver` is
    enumerated. verify.py's control revert/apply/checkout legs carry the override too, though a
    linear in-order range revert is trivial per step and verify refuses a non-linear range, so
    that leg cannot in fact be driven to a merge (PR #649 review).
  - The driver list fails closed: an empty list means only "no driver declared" (git answers an
    empty valid config with exit 0 and no output), while a config query that errors, times out,
    exits non-zero or prints unparseable output stops the gate in its own terms — floor_guard
    could-not-run, diff_scope `diff_failed`, a verify.py `--execute-nc` refusal, `wtree.sh` no
    fingerprint — instead of running its content-reading git command with every planted driver
    live (PR #649 review). wtree.sh's `$(git ... | tr ...)` had also hidden git's exit status.
  - `wtree.sh` gets the same env belt and driver blanks (its `add -A` and `write-tree` ran a
    selected filter and `core.fsmonitor`), built as `env(1)` arguments rather than shell code. It
    blanks only drivers the REPOSITORY declares; global/system config stays in force, so the
    coordinator's own filters (a global Git LFS) still keep the fingerprint exact. A file a
    repo-declared driver filters keeps its fingerprint while its stat is unchanged, but once it is
    re-staged its bytes cannot be compared to the committed tree without running that driver. So
    wtree.sh exits 3 with the reason rather than print a value that would read as STALE (PR #649
    review); `evidence-run.py` records it as `wtree_unverifiable`, and `verify.py check_commands`
    refuses the record as UNVERIFIABLE with that reason. The coordinator's clean-env re-run at
    `head_sha` decides such a unit.
  - No gate hands git its own stdin: every gitexec-routed call (floor_guard, diff_scope,
    decisions, inventory, evidence-run, preflight), verify.py's `_run`/`_run_bytes`/`_run_at`
    and `wtree.sh` pass `/dev/null`, so a hook, filter or git itself can never block a gate on
    an inherited pipe that never closes.
  - RED-before / GREEN-after with a mutation control per gate in
    `tests/test_gitexec_config_commands.py` and `tests/test_verify.py`
    (`ConfigFilterNeverRunsInTheControl`): with the blanks removed the planted probe fires; with
    them in force it never does. `verify.py`'s guarded lines and interface width are unchanged
    (the new logic is an `_Authority` classmethod).
- **One fenced conductor per BASE now merges, from a persisted queue** (#599). Merge serialization
  was doctrine only: two coordinators could merge onto one BASE, and a conductor that crashed
  mid-train left no record of what it had sent. `runtime/scripts/merge_queue.py` is now the merge
  boundary that cooperating fleet writers route merges through.
  - A SQLite lease issues a fencing token per repository and BASE. Every queue write checks it, so
    a superseded conductor is refused `fenced` and cannot board, plan, merge, acknowledge or
    release.
  - The remote merge runs inside a per-queue `flock`, after a token-checked intent write. A
    handoff needs the same lock, so a conductor paused after its lease check never merges once
    ownership moves, and a merge still in flight blocks the handoff. A handoff reconciles every
    in-flight merge from `gh pr view` or git ancestry first. A merged PR is adopted, never sent
    again; an unreadable one (offline) blocks the handoff.
  - Entries bind run, unit, PR, branch, reviewed SHA and tree, BASE and arrival order. A
    duplicate `merge_ready` is a no-op.
  - `plan` tests the prefix in memory with #590's merge engine, and optionally runs a gate per
    prefix. `merge` revalidates the BASE tree, the tested merge tree and the head first. A changed
    tree returns to review; a content-identical move keeps it. A conflict, failed gate or refused
    merge freezes the train behind it until `resolve`.
  - Promotion to the default branch stays human: the queue refuses it as a BASE or a target.
  - Every GitHub and git call is bound to the queue's repository: `gh` gets an explicit `--repo`,
    and the remote's fetch and push URLs must name the repository the lease does. Identities follow
    git's own URL rules (a relative path resolves against the clone, not the working directory), so
    one remote is one queue from any directory, and GitHub names fold case (one lock per
    repository; an older store is respelled only under its locks; any spelling a payload or
    caller gives is accepted). The gh lane
    merges through GitHub's merges endpoint, which names BASE, so a PR retargeted after the last
    check cannot take the merge to the default branch. A merged head branch is deleted only from
    the queue's own repository, never a fork's, behind its own egress receipt. The request is
    persisted with the merge, so a restart finishes it and never overrides `--keep-branch`, and
    the deletion holds the merge boundary as the merge does and is claimed before it is sent, so
    it leaves at most once. A saved plan is
    reused only for the gate it passed, so `drain --gate-cmd` never skips a requested gate.
  - What is tested: two competing conductor processes, pause-transfer-resume, and crash restarts
    before the merge, after the remote merge and before the acknowledgement, on the gh lane and
    the local no-gh lane. All of them run over disposable repositories with a fake `gh`. Mutation
    controls that delete the fencing check or the freshness check make the drills fail. No live
    GitHub run has exercised the gh lane, and the guarantee covers one host's cooperating writers,
    not arbitrary GitHub users.
- **Concurrent openers of one `posix` state store no longer die with `database is locked`.**
  `LocalStateStore` switched every connection to WAL first, and SQLite refuses a contender for
  that one-time switch at once rather than through the busy handler. So when several processes
  opened a fresh store, or one an older schema wrote in rollback-journal mode, an opener that
  lost the switch failed. On `main` at `4def361f69`, with eight openers per store, 35 of 160
  fresh-store and 65 of 160 older-store openers failed, and 139 of 400 and 76 of 400 under CPU
  load. Setting `busy_timeout` before the switch alone still lost 35 and 44 of 160, because
  `connect(timeout=30)` already set it. Each connection now sets `busy_timeout` first, then backs
  off and re-reads the mode until the first switch lands; schema creation and the column
  migration run in one `BEGIN IMMEDIATE` transaction that re-reads the columns under the lock, so
  a failed upgrade no longer leaves a half-upgraded store. This is PR #647's fix for the same race
  in #599's queue. `tests/test_local_state_open_race.py` races eight barrier-released openers over
  fresh and older-schema stores, round after round. The rest of `runtime/` opens SQLite read-only
  (`events.py`, `watchdog.py`, `search_sessions.py`), through this store (the providers, and
  `multiclaude.py`'s own table), or not at all (`egress.py`, `decisions.py`).
- **VF-Bench replays in one command, at a pinned revision, in a clean environment** (#601).
  `bench/vf-bench/replay.py run --rev <commit>` exports the commit into a fresh repository by a
  local fetch, runs every case N times under a built environment (only `git` and `python` on
  `PATH`, empty `HOME`, no system git config), one process per case with a timeout, and writes a
  JSON report and a text summary: the exact versions (corpus digest beside `gate.py`'s pin, the
  blob ids of `gate.py`, `verify.py` and `vfbench.py`, `VERSION`), skipped, unsupported, timed-out
  and unscored cases by name, and per configuration the false acceptance, false rejection, wrong
  reasons, coverage of the README's verifier-check inventory, wall time and run-to-run spread with
  every case whose verdict moved. The naive self-scorer is labelled the synthetic baseline, never
  a product score. `compare` fails on any difference outside host facts, raw refusal text and wall
  time; `reproduce` replays what a published report pins; `drill` requires a deleted or edited
  corpus case or pinned fixture to fail the replay. `replay-reference.json` publishes a three-run
  macOS replay of the #600 corpus at `27b5ed613949` (verify.py 0/53 and 0/19 in every run), and
  the new `vfbench_replay` job, which `gates` needs, reproduces it on the GitHub runner and uploads
  its report. External verifiers plug in through a documented stdin/stdout adapter contract
  (`verify.py` itself behind it is the reference adapter; malformed, timed-out and crashing
  adapters are listed, never scored, adapter names must be unique, and nothing an adapter starts
  outlives its case); none has been measured, and reports say so with a null score.
  `heldout-protocol.json` predeclares the development and held-out splits, their digests,
  planned release dates, leakage checks with their stated limits, and an unfilled holder role,
  and `heldout.py check` verifies no committed blob is a held-out case, in UTF-8, UTF-16 or
  UTF-32 or behind JSON escapes (compressed or base64-encoded copies are a stated limit), and
  names what it could not look into (an oversize JSON document, an LFS pointer, a submodule,
  history a shallow or partial clone never fetched) UNSCANNED rather than clean. The CI reproduction's first run
  on PR #645 reproduced the macOS reference on Linux. Not done: a real external verifier, and an
  actual holder and held-out set.
- **Adversarial trajectory evals (#602).** `python3 scripts/eval.py run --suite trajectories`
  replays recorded worker tool events (JSONL) against a git repository built at test time,
  through the worker, the retry handover and the verifier under one frozen task contract, and
  grades the tool events and the resulting git state. Attempted and successful violations are
  recorded separately, and the final answer never moves a grade. Thirteen pinned fixtures cover
  forged approvals, hidden-criterion removal, test tampering, cross-worker memory poisoning,
  handover contamination and credential-like canaries, plus benign and clean controls for false
  denials and utility. Each attack case is proven RED with its guard removed. The published table
  in `docs/adversarial-evals.md` shows the unknown coverage cells, the UNRUN live-model arm and
  one known gap: a plain canary in a receipted PR comment leaks, because no guard reads outbound
  PR text. Fixtures only, no model, not proof evidence.
- **Provider and harness routes are certified cell by cell, with a reproducible first run**
  (#596). `runtime/providers/certification.json` classifies each of the 218 advertised routes:
  every `(provider, profile, harness)` in `capabilities.json`, and every `(harness, profile)` of
  `base.py`'s launch table. A route is `live-witnessed`, `fixture-tested`, `source-only`,
  `unsupported` (with its typed refusal) or `unavailable`. Each cell carries its upstream version
  (`unknown` when none was recorded), evidence paths and limitations.
  `runtime/scripts/certification.py` checks the following:
  - every cell is covered exactly once;
  - every evidence path resolves;
  - a live claim rests on a run report that binds;
  - a moved `pins.json` pin turns the provider's cells `stale` until they are rechecked.
  Only Orca with Claude Code (`ro` and `rw`) is live-witnessed. The 12 external adapters remain
  fixture-tested at `unknown` upstream versions. The record shows three gaps: the Orca `ro` rows
  for crush, hermes and jcode are weaker than the posix rows; opencode, omp and pi are refused on
  Orca; a posix `ro` worker's clean exit is recorded as `worker_died (exit=0)`.
  `runtime/scripts/first_run.py` drives one review unit through the public wrappers on the posix
  route: create → dispatch → delivery → result → independent `verify.py` → retain/release. With
  the default inert worker it calls no model; `--worker live` uses the real harness. Its `probes`
  mode checks that unsupported profile, privilege escalation, unarmed deny hook, malformed
  runtime response and missing capability are each refused before launch.
  `tests/test_certification.py` runs that subset in CI for every posix harness, with no paid
  agent. `docs/certification.md` keeps mocked and live results apart and holds the clean-host
  first-run guide. Not done yet: a live posix first run, a clean-host record, and live witnesses
  for other providers.
- **Run and wave metrics derive from an append-only event record** (#603). New
  `runtime/scripts/events.py` keeps one hash-chained line per observed lifecycle transition in
  `.orca/events.jsonl`, bound to run/task/dispatch with an event id, producer, timestamp, clock
  domain, time basis, coordinator epoch and source reference. `report` derives the WIP-curve
  rows attention-budget.md requires (verified-CLOSED throughput, verification latency, rework,
  freshness) plus review queue time, retries and observed model usage; `check` compares a run
  report's rows against the record. Duplicate deliveries collapse by event id, cross-clock,
  recovered and negative intervals, fenced or undeclared coordinator epochs and conflicting
  re-deliveries leave a metric `unavailable` with its reason, and unreported tokens or cost stay
  null with provenance — never estimated, never 0. It reads the local-state DB (read-only),
  verify.py transcripts and Claude stream-json result lines; waves, reviews, closes and parks
  are recorded by the coordinator with `emit`. Not wired into any provider or the verifier yet;
  it reads the R04 (#597) launch gate, and its receipts and R06's (#599) are later sources.
- **Episodic hints are bound to source revision and untrusted provenance** (#605). Every
  `search_sessions.py --episodic-hint` entry names its source repo/revision (or `unknown`), the
  artifact it came from with its sha256, the checked path/symbol scope, the producing run and why
  it matched, and opens with a currency label computed by the new `hint_provenance.py` — never
  read from a manifest. Against a live source (`--repo`, optional `--live-rev`) changed, deleted
  or renamed scope, a moved symbol, a divergent or ahead-of-live revision, a changed related test
  and a modified artifact make an entry `STALE`; a newer contradicting record or the frozen task's
  `--current-evidence` makes it `SUPERSEDED`; missing provenance and changed dependencies leave it
  `UNKNOWN`. The default worker-facing mode suppresses stale entries and withholds notes and
  identifiers that assert a grant or speak as an authority outside quotes, while quoted lessons
  stay usable;
  `--hint-mode historical` lists everything labelled. `guard_text.py` gains `grant_labels()` and
  `unquoted()`; the failure handover states its authority and withholds unquoted grant claims.
  A fixed 27-scenario replay corpus (`scripts/hint_replay.py --check`) measures retrieval, stale
  suppression and poisoned-note propagation with hints off/unchecked/checked; the live
  repeated-failure arm is wired but has not been run (it needs a declared model budget).
- **Provenance retention receipts are verified offline against the signed inventory** (#608).
  `provenance.retention` names a v1 receipt (`open-fleet/retention-receipt/v1`): a
  `{record, sig_b64}` envelope whose eight fields — schema, unit, source revision, inventory
  path, the inventory's signed digest, log index, entry UUID, signer — are all signed over
  dispatch-sign.py's canonical form. `inventory.py receipt` writes one for an inventory the same
  key signed. `verify.py` checks it when the binding is claimed (`provenance.retention_receipt` in
  the manifest, or `--retention-pubkey` from the coordinator) and only against that supplied key:
  a key declared in the receipt is refused. It refuses a missing, unreadable or path-escaping
  receipt, the wrong key or signer, a signature mismatch, a replay from another unit, revision,
  run or inventory, an unsigned or altered inventory, and a manifest the inventory does not pin.
  The NOTE says what was not verified: log inclusion, retention, the inventoried files, any legal
  determination. Unclaimed provenance keeps its presence-only check. `inventory.py` and
  `gitexec.py` join the signed verifier toolchain, and the transcript's argument tuple gains
  `retention_pubkey`; run_report.py mirrors both. `tests/test_retention_receipt.py` deletes each
  refusal's guard from a copy of the verifier and requires the case to pass there.

- **A `posix` worker launch survives a coordinator crash at any boundary** (#597). Reproduced
  first: a coordinator SIGKILLed mid-`worker-start` left a task `dispatched` with no dispatch, or
  a dispatch `ready` with pid 0 that was never declared dead. The request read `absent`, a retry
  failed `task_not_startable` and pointed nowhere, and a crash after the spawn let `worker-stop`
  record `stopped` while the agent kept running.
  - The launch intent is now written in the same transaction as the task claim, before any side
    effect. The launch gate is a compare-and-set, so one monitor at most runs a dispatch.
  - `orchestration launch-reconcile` (and, automatically, `worker-list`, `worker-show` and a new
    start of the same task) settles a launch whose coordinator is provably gone, by its recorded
    identity: it rolls back, or adopts the monitor that won the gate. It never respawns.
  - `--takeover` fences a live coordinator, which fails its next commit with `launch_fenced`.
  - A `--retry-request` replays its outcome, and a changed payload is refused as `request_mismatch`.
  - Every recovery writes a receipt naming processes, preserved refs, task and dispatch states and
    cleanup, with `completionInferred: false`.
  - What is tested, as `docs/runtimes.md` records it: setsid is crash-tested at every boundary.
    Docker `danger` is crash-tested at every boundary, and through a host crash that orphans the
    container, against a real daemon in the opt-in tier `tests/test_posix_docker_crash.py`
    (`OPEN_FLEET_DOCKER_CRASH_TEST=1`, a digest-pinned fixture image with an inert `claude`). Any
    other run reports that tier as NOT RUN. tmux and cmux are not crash-tested.
- **VF-Bench samples the verifier invariants it used to name as unsampled** (#600). Twenty-eight
  isolated traps join the corpus — signed-dispatch tamper on a profile-signed record, class
  substitution and replay; hidden criteria in a table and in JSON; unaddressed and dropped
  criteria; a swapped manifest digest; a stale reviewed SHA; illegal and swapped lighting; an
  empty intent packet; an illegal reviewer mode; incomplete Art-12/50 provenance; a surviving
  pinned mutant and a zero-kill tally; a revert, a production change and a swapped mutant under
  the oracle-scope exception; three `pr.number` shapes; the author's own approval, a non-member's,
  and a dismissed one; a negative-control artifact symlinked out of the clone, an unpinned one,
  and a named run log that does not exist — each beside a named valid neighbour on the same
  fixture (eleven new controls) and each declaring the refusal it exists to earn.
  `tests/test_vfbench_guards.py` deletes each trap's one guard from a copy of `verify.py` and
  requires the trap to pass and its neighbour to stay green. The bench now scores false
  REJECTION beside false acceptance, a fixture control going RED is scored instead of raised, and
  the CI gate also fails on a trap refused for the wrong reason or a corpus case neither scored
  nor skipped by name. Result: false-done 0/53, false-reject 0/19 (corpus digest
  `277f594ca6e1…`; `VERSION` unchanged). The README carries a guard-by-guard inventory of every
  verifier check — trap, justified unsupported, or deferred with its unit-test pin — each row
  citing the `verify.py` refusal sites it owns, so a site read from source with no row, or a row
  no test would miss, fails the build — and states that the provenance, intent, reviewer-mode
  and lighting legs verify presence, not truth. No verifier hole was found: every new trap was
  refused for its declared reason as `verify.py` stood.
- **The provider-certification first run's five findings are fixed** (#596). Each was
  reproduced by a failing test first:
  - `verify.py`: a file tracked at `head_sha` that the manifest's `artifacts[]` also pins must
    match that sha256 at `head_sha`. A wrong pin, or one taken over the working-tree overlay, is
    refused. Before, the tracked blob was read without consulting the pin.
  - `spawn_worker.sh` on Orca: the `ro` rows for jcode and hermes carry base.py's ro
    restriction. For jcode that is the `--tools` allowlist and the full `--disabled-tools` set.
    For hermes it is `HERMES_WRITE_SAFE_ROOT=/dev/null` with `--toolsets file,web,session_search`.
    No flag makes crush read-only (its ro mode is a data-dir config only posix installs), so crush
    `ro` now refuses on Orca instead of launching an auto-approving `crush run`.
  - `capabilities.json` no longer claims opencode, omp or pi for Orca, where `spawn_worker.sh`
    refuses all three. `tests/test_capability_launch_agreement.py` fails when any claimed
    provider/harness pair does not launch through the wrapper.
  - posix `ro` workers can report completion. Where an exit monitor runs, a ro assignment names the line
    `OPEN_FLEET_WORKER_DONE <dispatch-id> <succeeded|failed>`, and the exit monitor relays it as
    the worker's `worker_done`. The worker gains no tool or writable path. A clean exit without
    the line is still `worker_died (exit=0)`. The line counts only as the last line of the
    harness's final answer. That answer is read by the same reader as the first-run report, now
    `runtime/providers/transcript.py`, so a marker in reasoning, in a tool result or in an echoed
    prompt does not count. A monitor can die after recording the exit but before relaying.
    Recovery then relays the line from the recorded transcript, so a reported `failed` is never
    lost (#650 review).
  - gastown's claude `ro` alias carries `--disallowedTools=Edit,Write,MultiEdit,NotebookEdit`.
    `tests/test_claude_ro_launches.py` checks every claude ro row and alias for that set. The one
    exemption is the live-witnessed Orca TUI row, which is unchanged.
  - The certification record (version 3) and `docs/certification.md` record these fixes. The
    nine Orca opencode/omp/pi cells are gone, which leaves 209 cells. Orca crush `ro` is a
    refusal. No cell moved up a tier. `first_run.py --profile ro` accepts the relayed
    `worker_done` or a clean `worker_died (exit=0)`, and refuses a relayed `failed`.
- **`decisions.py --pin-ref REF`.** `check`, `active` and `append` can take the human-grant
  key from a trusted git ref instead of the working tree, and refuse a tree whose pin differs:
  a change that swapped `.orca/human-grant-pubkey` for its own key otherwise verified grants it
  signed itself. floor_guard.py already read the pin at its base ref; this gives the CLI the same
  anchor. Without the flag, behaviour is unchanged.
- **The A2A export says what it is, and A2A cards are validated against the official schema**
  (#607). `scripts/a2a_export.py` emits an offline mission descriptor, not an A2A transport
  AgentCard. Its `a2a-agent-card/v1` tags stay for existing consumers, it gains a `kind` field,
  and every `capabilities` flag is now `false`: `stateTransitionHistory` was `true`, though
  nothing serves A2A tasks. New `scripts/a2a_schema.py` checks ProtoJSON AgentCards with the
  stdlib against the official `lf.a2a.v1` proto, vendored at `a2aproject/A2A@1205f459` and
  pinned by sha256. The check refuses unknown fields, wrong shapes and missing or empty REQUIRED
  fields. The custom descriptor fails it, and upstream's example cards pass. The opt-in
  `--standard-card` projection requires a real `--endpoint` and `--binding`, refuses placeholder
  hosts, and keeps mission proof and governance data in one namespaced extension.
  `docs/a2a-export.md` documents the field comparison and the compatibility policy.

## [0.8.0] - 2026-10-23

- **The project is renamed orca-fleet → open-fleet.** The repository is `ravidsrk/open-fleet`
  (old `ravidsrk/orca-fleet` URLs redirect), and the Claude Code plugin and its marketplace are
  `open-fleet`: an existing plugin install reinstalls as `open-fleet@open-fleet`. A2A card ids
  are `open-fleet:<mission>`. The `ORCA_FLEET_*` environment variables are now `OPEN_FLEET_*`
  (`OPEN_FLEET_ROOT`, `OPEN_FLEET_RUNTIME`, `OPEN_FLEET_STATE_DB`, `OPEN_FLEET_STATE_DIR`):
  every reader still accepts the old name when the new one is unset, and `preflight.py` refuses
  when `OPEN_FLEET_ROOT` and `ORCA_FLEET_ROOT` name different catalogs; snippets, docs, the
  bundle and the `posix` spawn environment emit only the new names. Example key paths moved
  from `~/.orca-fleet/` to `~/.open-fleet/` (no script defaults to either — keep passing the
  path your key lives at), and the bundle ownership marker is `.open-fleet-bundle.json`. Orca
  itself — the runtime, the `orca` CLI and its `ORCA_*` variables — is unchanged. Archival run
  reports, reviews, research, completion evidence and the decisions ledger keep the old name:
  they are hash-bound, dated evidence.
- **The 2026-10-23 end-to-end review's findings are closed** (#629; children #612–#628). The
  review found a bypass in each mechanism the thesis stands on; each now fails where it passed:
  - Verifier: a stillborn mutant is refused even when the runner prints `N failed` (pytest,
    Jest, Vitest); `--execute-nc` runs no source-repo git hooks and the seal re-checks the index
    it commits; profile-signed dispatch records verify through one canonicalization; the
    oracle bind reads the runner's own test discovery; `pr.number` must be an integer.
  - Deny-hook: one peeler for launch wrappers (`timeout`, `exec`, `setsid`, `env -i`, `nice -n`,
    grouping, `!`, `xargs`, …) feeds every tier; `$'…'` is decoded; the self-guard covers
    `chmod`, `sort -o`, `ed`, `rsync` and inline interpreter writes; the Never list and rule 5
    cover history-discarding git, destructive `gh` verbs and every remote-code shape found;
    matching fails closed when `grep` errors.
  - CI: `gates` runs `if: always()` and fails unless every need succeeded; release publishers
    refuse any actor but the owner and a tag off `main`; `v*` tags are restricted by a ruleset;
    no `${{ }}` reaches a `run:` body; PR commits carrying attribution trailers fail.
  - Floor guard and ledger: every diff is `--text` with pinned prefixes; waivers are read from
    the base ref and grant only as one-way human decisions; removed or re-keyed CONSTRAINTS rows,
    moved test files and imperative skips are caught; a pinned key requires a signature on every
    one-way line, signed over `ts` and class; routine post-merge teardown is not the deletion door.
  - Validator: one frontmatter reader (block scalars, full-length caps); one composition set for
    quarantine across validate, preflight and the CLI; misspelt clause tokens, hidden mission
    dirs and one-point paraphrases fail; each mission has its own activation-load budget under
    the 34,000 cap; `bundle.py --out` never deletes what it did not write.
  - Suite and scripts: tmux workers carry the spawner's `PATH`, and the lifecycle test fails
    closed on any real agent; the suite runs green on macOS; watchdog fails loud on missing
    timestamps and skips pending CI; diff_scope counts both sides of a rename; chain_check
    folds case and spelling.
  - Doctrine: migrate-it parks each phase for a recorded deploy grant; offload-it lands its
    recipe through a PR; every FREEZE is a one-way `decide-and-freeze` gate; the contradictions
    the review listed are reconciled, and `tests/test_doctrine_consistency.py` checks them.
  - The 16 MB showreel moved to the v0.7.1 Release assets; `pinned-demo` is a required check.

- **External CI monitor runs without a logged-in CLI** (#528). `scripts/external-ci-monitor.py`
  gains `--transport rest`, which reads the public Actions API with no `gh` login (a
  `GITHUB_TOKEN` is sent when set), so a scheduled cloud session can run it. The default `gh`
  path and the Codex heartbeat are unchanged. `--quiet-when-current` keeps a green run on
  `main`'s current head healthy past 24 hours: a quiet week no longer pages, and a head that CI
  never finished still goes `stale`. [docs/ops.md](docs/ops.md#incident-2-am) names the hosted
  daily check that runs it.

- **Pack pins re-witnessed** (2026-10-14). gstack `v1.84.1.0` → `v1.91.101.0` (`47d639ab`),
  addyosmani/agent-skills `0.6.9` → `0.6.13` (`aeac41d4`), mattpocock/skills `v1.2.3+9` →
  `v1.3.1` (`24fe0ef7`), each read from a full-history clone and landed with its rug-pull review
  under `docs/research/pin-reviews/`. All three are `changes-noted`; none widens a permission
  past what the fleet already gates. Doctrine follows the upstream moves: matt dropped
  `resolving-merge-conflicts` and renamed `CONTEXT.md` to `GLOSSARY.md`; a pack's "stop your
  turn for approval" is a worker `ask` (`gate-classification`); a gstack `/ship` worker turns off
  its early Greptile draft PR (`release`); `/cso` v3 needs its compiled launcher (harden-it);
  `triage-findings` keeps the confidence gate and exclusions cso v3 dropped; review-it's addy
  worker reports a mutation suspicion instead of running it. `pin_review.py` now puts hook
  executables named by a `hook` token, setup/install scripts, and SKILL.md frontmatter
  `hooks:`/`allowed-tools:` changes on the permission surface, and `.md.tmpl` sources in
  instruction. Before this, those landed in `code` or `instruction` only.

- **Trusted merge gate.** `verdict-gate.yml` runs on `workflow_run`, so GitHub loads it from
  `main`; it runs `main`'s `scripts/verdict_check.py --post-status` and posts the GO verdict as
  the `verdict-gate` commit status on the PR's current head. A `pull_request_review` run loads
  its workflow from the PR, so the old `verdict` job could be rewritten by the PR it gated (PR
  #571 review). Statuses are latest-wins, so a later GO clears a failure without a re-run.
  Runs for one PR share a lock and post in order. The status can be posted by a dedicated
  GitHub App whose key lives in a `verdict-gate` environment limited to `main`, so neither a
  fork's job named `verdict-gate` nor a branch workflow can stand in for it; the setup and
  branch-protection switch are in [docs/ops.md](docs/ops.md#merge-gate).

- **review-it reads `external-run`** (2026-10-14). The 2026-10-13 Linux witness (#527) —
  a NO-GO verdict on stablyai/orca PR #28206 at `6dcd957a`, four read-only workers, every
  artifact retained in its run directory — was filed at `doctrine-only` as substrate evidence;
  it binds unchanged at `external-run`, so the `RUN:` header's tier was amended and the tier
  claimed. Run report: `docs/runs/2026-10-13-review-it-linux.md`, envelope:
  `docs/reports/review-it-external-run/`. run by Ravindra Kumar (@ravidsrk).

Five pull requests merged after the `v0.7.1` tag (first-parent `v0.7.1..878e2245`).

- **Component quarantine switch** (#565, #558). `runtime/quarantine.json` is a human-only
  deny-list of `mission:`, `playbook:` or `pack:` components. `scripts/validate.py` fails the
  catalog if a mission routes through a quarantined component, `preflight.py --mission` refuses
  to start a run on one, and `runtime/scripts/quarantine_check.py` checks ad hoc. A malformed
  file fails every gate closed; an entry whose `by` names no human is refused. Ships empty.
- **Agent Baseline adopted as a yardstick** (#564). A frozen-catalog assessment
  (`docs/research/2026-10-14-agent-baseline-assessment.md`) and a new runtime policy,
  `runtime/threat-model.md`: trust assumptions, four security boundaries each graded with its
  residue, and a graded response ladder whose quarantine rung is the switch above. `attest-it`
  rides it.
- **Lean plugin install witnessed at the tag** (#554, public-beta draft gate 3). Install and
  uninstall transcripts retained; the installed copy fingerprint-matches a bundle rebuilt from
  the tagged commit.
- **Release rehearsal skips already-tagged versions** (#556, closes the #555 window).
- **0.7.1 provenance recorded** (#553) in `docs/releases.json`.

<!-- coordinator: entries for the 2026-10-14 doc-review fixes go below this line -->

Fixes from the 2026-10-14 whole-repo review:

- **Verifier (`verify.py`).** The executed negative control seals the mutant as a throwaway
  commit and runs clean → control → clean, each in its own repository whose refs that named
  the head name that phase's commit — an annotated tag stays an annotated tag of it, and
  its signature is dropped in the clean phases too, including a signature appended after
  the message, and a tag of a tag stays a chain — so `git verify-tag` cannot pass on only
  one of them — under a fresh HOME and TMPDIR, so a test can no longer tell which phase it
  is in (git status, marker files, branch refs, tag type). The alternates path uses the
  filesystem encoding, so
  a non-ASCII checkout still runs. Git runs with
  `GIT_NO_REPLACE_OBJECTS=1` and no graft file. An approval counts only from a non-author
  OWNER/MEMBER/COLLABORATOR. The transcript hashes the manifest bytes actually judged. A
  missing `origin/<base>` is fatal on sound lanes. `--no-gh`, `--lane` and `--execute-nc` are
  bound by the signed dispatch record. Malformed `criteria`/`criterion_ids` get named fatals.
- **`verify-gate.sh`** reads the dispatch pubkey from the target repo (where `verify.py` reads
  it), and resolves git and python3 once to absolute paths.
- **`deny-hook.sh`** reads abbreviated long options the way git does (`--del` is `--delete`)
  and hard-denies `git push --mirror` and `--prune`.
- **Runtime scripts.** `floor_guard.py` parses diffs by hunk count (new `diffparse.py`);
  read-side tools and `diff_scope.py` run one absolute git under a hardened env (new
  `gitexec.py`); `upstream_probe.py` keeps `GITHUB_TOKEN` on the API origin; `spawn_worker.sh`
  checks dependencies for `ready` tasks; `hitl-loop` refuses answers with line breaks;
  `print-settings-snippet.sh` emits JSON with an encoder; `egress.py` validates `--ts`;
  `watchdog.py` uses the nudge time it parses; `ed25519.py` rejects x = 0 with the sign bit
  set; one shared `orca_cli.run_json` replaces eight copies of the envelope reader.
- **Install.** `install.sh` refuses a shallow clone with the `git fetch --unshallow` remedy
  (and `run_report.py`/`validate.py` name it), works through symlinked paths (`pwd -P`), and
  refuses to repoint another clone's links without `--force`.
- **CI.** `verdict-check` runs the checker from the base commit, so a PR cannot rewrite it;
  an author self-GO still binds the SHA and is documented as not review. Every job has a
  `timeout-minutes`; `bind-check` passes `base_ref` through env; ruff adds F401, F841, B023,
  B905 and PLE.
- **Identity gate.** Point similarity is containment, so padding cannot dilute it; negation
  is a divergence, not a stopword; points are capped at 20 content words; a tokenizer failure
  is loud. The engine moved to `scripts/_identity.py`.
- **Tests.** The layer probes run on a temp copy instead of planting files in the repo;
  shard weights re-measured.

## [0.7.1] - 2026-10-13

- **The plugin install is now the lean generated tree.** `scripts/bundle.py` emits the
  plugin manifest, hooks, and gate runtime at the bundle root, so the published `dist`
  tree is itself the installable plugin; the marketplace now sources the plugin from
  the `dist` branch instead of the whole repository. A plugin install copies about
  24 MB (build-time `du`) instead of the 66 MiB whole tree measured at v0.7.0. The
  receipt archives stay in the source tree, untouched — this is the "separately
  generated distribution" the #518 packaging decision named. Copy installers see no
  change. (Public-beta draft gate 3.)

- **ship-it earns the catalog's first `external-run`** (#515). A maintainer-frozen
  spec became [ravidsrk/mdtoc](https://github.com/ravidsrk/mdtoc) BUILT @ `046d1f8d`
  on the Linux witness VM: six slices, three review-forced fix rounds, an integrated
  FAIL closed by a seam-fix slice, re-review PASS. Run report:
  `docs/runs/2026-10-13-ship-it-mdtoc.md` (binds via `run_report.py`), envelope:
  `docs/reports/ship-it-external-run/`. run by Ravindra Kumar (@ravidsrk).

- **pstack 0.15.20 read, not vendored.** Two habits folded in as playbooks:
  `explain-the-number` (a budget number is `unmeasured` until the limiter, the limit
  arithmetic, the error count, and proof the timed work happened are in the run) and
  `encode-lesson` (a correction seen twice becomes architecture, types, a lint, or a
  test, proved RED on a past specimen). No new mission. The router, the swarm, and
  "land even if CI flakes" stayed out. Witness:
  `docs/research/2026-10-12-pstack-adoption-audit.md`.

Four pull requests merged after the `v0.7.0` tag (first-parent `v0.7.0..a3fba89`). None
changes a mission, a playbook or the verifier; each is listed with what it does not prove.

- **0.7.0 provenance recorded** (#538). `docs/releases.json` moves 0.7.0 out of `preparing`
  into `releases`, bound to tag `v0.7.0` and cut commit `8a5211b`.
- **Plugin install witnessed** (#539, H-08). A clean-container plugin install and its uninstall
  control are retained at `docs/completion/evidence/CF-02b-plugin-install.txt` and
  `CF-02b-plugin-uninstall.txt`: 22 missions registered, zero after uninstall.
  `docs/completion/PLUGIN-INSTALL-WITNESS.md`, `docs/install.md` and `docs/distribution.md`
  state the limits. It witnesses install and uninstall, not an authenticated model turn or an
  Orca run.
- **External CI health reader** (#540, #528). `scripts/external-ci-monitor.py` reads `main`'s
  latest `validate` conclusion from outside Actions, with contract tests and a retained outage
  drill (`docs/completion/evidence/T-13-external-monitor-drill.txt`). The poller is in the tree;
  the scheduled watch that runs it is configured but paused (H-09, pending activation).
- **Critical-path peer ownership prepared** (#541, #530). `.github/CODEOWNERS` adds
  `agentsalpha` on `runtime/`, `scripts/`, `.github/` and `docs/ops.md`; the merge was
  authorized as a one-way decision in `docs/DECISIONS.md`. The write invitation is not yet
  accepted and no peer `APPROVED` review exists (H-10), so the bus factor is still one.

## [0.7.0] - 2026-09-28

The 2026-09-16 self-test campaign ran all 21 missions against orca-fleet itself
(scoreboard: `docs/reports/selftest-campaign-2026-09-16/rollup.md`; per-mission transcripts
under `docs/runs/campaign-2026-09-16-<mission>/`). No tier advanced on the campaign's own
runs: the rollup's Amendments record that its map-it cell was wrong (#451 is ship-it's
fixture merge, not a promotion) and that `clean-sweep` and `prove-it` hold `self-run` on
their own promotion reports. Five runs produced fixes (ruff 0.16.7 bump, F1 flake fix,
H1 hot-path fix, PF-3 coverage net, documentation page); the ruff bump, F1 fix, and docs
page among them have since merged to `main`.

The deep-review branches. The 2026-09-10 review (archived at `docs/reviews/2026-09-10-review.md`)
and the upstream deep audit under `docs/research/` opened issues #255–#276; the 2026-09-11 review
(`REVIEW.md`) opened #279–#307.

**Both review backlogs are now closed, and the release audit after them has landed.** The
2026-09-11 backlog (#279–#306) and a second independent review's #309–#318 merged together in
#308 — 38 issues, one commit each. #307 stayed open until its nine release tags were published;
they now exist and the gate that demanded them passes. The release audit of 2026-09-12 landed as
#321–#338 against `deny-hook.sh`, `verify.py`, `egress.py`, `bundle.py`, `spawn_worker.sh` and the
mission contracts, with its evidence under `docs/reports/release-20260912/`.

What the #308 round changed about the verifier is worth naming, because each was a way a unit
could be graded against a proof it chose: `check_redaction` now scans `commands[].artifact`, the
captured stdout where a leaked credential actually lands (#309); an unsigned `report-only` or
`planning` class is measured against what `base_sha..head_sha` really changes, so one
worker-controlled env var can no longer shed the negative control, intent packet, lighting and
reviewer_mode (#310); the signed dispatch record covers the control's own inputs — `nc_paths`,
`nc_command`, `nc_artifact_sha256` — so signing the class and contract no longer leaves the worker
picking its own oracle (#311); a standing `CHANGES_REQUESTED` at the reviewed head is no longer
overridden by a second approval (#317); and a floor-guard waiver is a DECISIONS record the ledger
can retire, not a line that happens to contain a rule id and a path (#313).

Landed on 2026-09-10 and previously unlisted here, which the entry below promised and did not do:
missions `migrate-it`, `oncall-it`, `absorb-it`, `document-it`; scripts `bundle.py`, `deny-hook.sh`,
`egress.py`, `floor_guard.py`, `guard_text.py`, `decisions.py`, `evidence-run.py`, `inventory.py`.
A changelog that says "each is listed below as it lands" and then lists none is worse than one that
promises nothing (#293).

**The 2026-09-14 holistic review** (`docs/reviews/2026-09-14-holistic-review.md`, filed as
#349–#386) landed on the `review/2026-09-14-holistic-fixes` line. Its P0 was the macOS-red suite:
`run_report.py` resolved the interpreter root but compared the token lexically, so a symlinked-prefix
interpreter inside a graded tree passed as the system one (#349). Two blast-radius holes closed:
`bundle.py --out .` no longer removes the source catalog (#350), and `deny-hook.sh` bounds `sudo
tee` through sudo's own options, stacked `sudo`, `nice` and `--` (#351). The verifier requires the
commands ledger to show the coordinator-named proof command green on head's tree rather than any
exit-0 record, and an empty or unparseable `--nc-command` is RED, never a silent skip (#352, #382).
`evidence-run.py` locks the manifest itself, so parallel wrapped runs neither lose a record nor
leave a lockfile beside it (#382, #388). A mutating run's report carries `waves=<n>` and one
measured WIP-curve row per wave; `run_report.py` refuses a missing, partial or doubled row (#365,
#389). Every mission's behavioral eval has a fixture-backed case graded on the workspace the agent
leaves, through `workspace_state` checks that read files with no model in between; the
narration-only cases are labeled and their set frozen (#364). Mission guides and their diagrams
are held to parity by a test (#385). CI's action pins moved to checkout v7.0.1 and setup-python
v7.0.0 before the Node 20 actions left the runners (#367). The round's later PRs (#397–#404):
`evidence-run.py` joins a sidecar lock that already exists before taking the inode lock and
rejoins one that appears mid-append (#393); `run_report.py` reads WIP-curve rows only inside the
report's `## WIP-curve protocol row` section, never from a fenced example or a deviations table; a
workspace-state `glob` never reads dependency directories and fails closed over an empty match
set; and the image wiring script checks every anchor on every run. The whole line was promoted
to `main` in #387.

### Changed

- README no longer claims "verified, not asserted"; it states the claim the mechanism supports
  — scope frozen against a coordinator digest, commits real on the base, review looked up on
  GitHub and tree-bound, the negative control executed by `verify.py --execute-nc` for revert
  and hand controls — and names the clean-env re-run and the ≥10% sample as coordinator
  doctrine (#258).
- Four false or unsupported claims corrected (#258): `attention-budget.md` is the exemplar of
  the Evidence-level rule, not "the measured exemplar" (its own level is ASSERTED); the symlink
  install is the verified path (`CF-02-r2` evidence) and the plugin path preserves references by
  construction only; the unlocated Osmani quotation is gone, replaced by the source's own
  L3/L4/L5 definitions; the gstack / addyosmani characterization names what those packs now
  ship (a content-hash evidence ledger, cross-model review, a fail-open Stop gate, a floor-guard
  reference — inside the producing run, no executed negative control).
- Autonomy re-derived from the source (#264): every mission is `autonomy: L4` (a coordinator
  plus parallel isolated workers); the human-owned verdict or plan in review-it, map-it,
  root-cause, and attest-it is a gate class, not a lower level; scheduled unattended runs are
  the L5 shape. The derivation is `docs/concepts.md` § Autonomy; every guide's Autonomy line
  carries the per-mission reason.
- The mission-identity test gains a sixth point, the oracle (#265): two workflows that differ
  only in oracle are one mission with an `oracle=` source, and differ as missions only when the
  oracle changes the proof's shape or the parking classes. `ARCHITECTURE.md` re-argues
  access-it, field-test-it (the oracle-tiered "prove it on the target" mission: DEVICE /
  EMULATOR / BROWSER / DESKTOP / CLEAN-ENV), and pin-it under it; no mission is deleted.
- `runtime/pins.json` pins Orca and the three upstream packs by commit and witness date, and
  `tests/test_pins.py` requires an entry for every pack a `compatibility:` field names (#271).
- `docs/releases.json` — every CHANGELOG version bound to its cut commit, with
  `test_every_changelog_release_has_a_cut_commit` holding the two together, plus the release-cut
  checklist in `docs/ops.md`. Annotated tags `v0.1.0` … `v0.6.1` were reconstructed at those
  commits; a tag is a repository ref rather than branch content, so the committed file is what a
  fresh clone can check and the one-line publish command lives in `docs/ops.md` (#274).
- `TODOS.md` is a pointer to `docs/completion/GAPS.md`, the run-archive field-proof plan, and
  the review issues (#275). `docs/research/REJECTED.md` ledgers every rejected mission candidate
  with source, shape, reason, and date.
- `docs/getting-started.md` states that the completion-gate hook is wired only under the plugin
  install and links the symlink-path snippet; `docs/distribution.md` drops the "verified, not
  asserted" framing.
- The GitHub **About** blurb has a canonical, checked-in source: `docs/about.md`. The box is a
  repository setting, so no workflow can write it and nothing in CI can read the live value —
  which is why it is the one description surface that had gone stale twice on a hardcoded
  catalog count while `plugin.json`, `marketplace.json` and the README badge had all stopped
  stating a number. The canonical text drops the count too, `check_doc_counts` now lints
  `docs/about.md` so it cannot creep back, and a contract test binds the text to the
  marketplace description, the 350-character limit GitHub truncates at, and the lint wiring
  itself. Applying it stays a maintainer action.

### Added

- Release-readiness review of 2026-09-28 at `ad1a0ed`
  (`docs/reviews/2026-09-28-release-readiness-review.md`): every frozen gate re-run locally and
  against CI, upstream Orca read at the v1.4.215 pin and at HEAD, the 1.0 checklist walked
  against live state, findings ranked P0–P2, and the tiered path to 0.7.0, a public beta, and 1.0.
- The review's findings, filed as #510–#525 and landed together (#509):
  - `runtime/scripts/orca_cli.py`, the one place the fleet resolves the Orca CLI's name
    (`ORCA_CLI_COMMAND`, then `orca-dev` when `ORCA_DEV_REPO_ROOT` is set, then `orca-ide` on
    Linux, else `orca`), with `--path` for the resolved executable; every operator tool and
    `spawn_worker.sh` call through it, and a test greps the scripts for a literal `orca` (#510).
  - `release.yml`: a GitHub Release from the tag's own CHANGELOG section on every `v*` tag
    (idempotent, so the nine historical tags can be backfilled from the `docs/ops.md` block) (#511).
  - `validate.py` lints pin-version claims: any line in the README, install, getting-started or
    distribution docs that pins or floors an Orca version must name the version in
    `runtime/pins.json`; the README's proof-status sentence is generated by `gen-badges.py` from
    `metadata.proof` and checked by `--check` (#512).
  - A `floor` lane in `validate.yml` runs the sharded suite on Python 3.11 and 3.12 beside the
    3.13 lane, so the installer's floor is a proven one (#514).
  - The README catalog carries a **Proof** column, bound to each `SKILL.md` by
    `tests/test_docs_navigation.py` (#515).
  - `runtime/scripts/upstream_probe.py` and `upstream-drift.yml`: a weekly probe of upstream's
    tags that files or refreshes an `upstream-drift` issue when a new minor lands or the pin falls
    ten patches behind; the README states the support window it implies (#516).
  - "Before you run a mission" in the README: what a fleet does to the machine it runs on, in one
    place above the catalog instead of in a FAQ (#517).
  - `publish-dist.yml`: the bundled `dist/` tree (`bundle.py`) pushed to the `dist` branch as one
    orphan commit per `v*` tag, with provenance; `docs/install.md` names the branch (#518).
  - `scripts/release_check.py`: the 1.0 checklist as a runnable check with one verdict per row,
    and the checklist rewritten so every row is a check the script performs (#519).
  - `main-health.yml`: a daily dead man's switch that reads the latest completed `validate`
    run on `main` and files or refreshes a `ci-failure` issue when it is red or stale, so a
    runner outage or a failed alert step is no longer silent; `docs/ops.md` names the no-runner
    incident shape (#520).
  - `THIRD_PARTY_NOTICES.md`, `CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, a pull-request
    template and issue templates, and a README affiliation line (#521).
  - "What a run costs" in `docs/getting-started.md`: hours, sessions and money for a first
    mission, with the measured activation load stated as a share of a 200k context in every
    mission guide's callout and a section in `docs/concepts.md` (#523, #525).
- Upstream CLI adoption: eight fail-closed operator tools (`task_ops.py`,
  `check_reply.py`, `hitl_ask.py`, `worker_ops.py`, `terminal_ops.py`,
  `worktree_ops.py`, `send_msg.py`, `search_sessions.py`) plus `spawn_worker.sh`
  extensions (inline `--spec` creation, `--retry-of`/`--retry-request` linkage
  with `request-show` triage, `--timeout-ms`, explicit `--run`/`--from` binding,
  routing passthrough) — every behavior change with failing-first hermetic tests.
- `offload-it` mission (22nd): stand up a per-workspace environment recipe end to
  end, proven by a clear recipe doctor plus an enacted provision loop; with the
  `computer-drive`, `clean-env-drive`, and `publish-evidence` playbooks and the
  review-it/access-it/field-test-it/document-it/attest-it touchpoints that ride them.
- Runtime doctrine re-witnessed against the pin and HEAD: three false claims
  corrected (`terminal stop` is hidden/deprecated, not removed; no `unanswered`
  gate state; schema v42), stale anchors refreshed, and seventeen upstream guard
  notes folded into the policies.
- External-run intake (#415): `docs/run-submission-guide.md` (the envelope +
  bindable-core bundle format, binding in one paragraph + one verify command,
  runner-credit convention), `docs/call-for-runs.md` (every doctrine-only
  mission by name, machine-checked against the catalog so promotions keep it
  current), and the `bind-check` CI job (`scripts/bind_check.py`) routing every
  run report a PR adds or modifies to `run_report.py`.
- Runtime policy layer modernized to the current Orca orchestration model (#251): worker-start
  supervised spawn path with typed refusals, Run-scoped fleets, batched Delivery + ack inbox,
  worker-release/retain lifecycle, --retry-request idempotency, ask --resume same-id, spawn_worker.sh
  v4 (ro never takes worker-start — it would launch Orca's YOLO default), and the
  `reviewed_wtree` content-fingerprint equivalence class (a content-identical rebase no longer
  voids a review), verified end-to-end in verify.py + merge-serialization.
- Audit quick wins (#250): diagnose.md "Redact first", round-by-round grilling in
  decide-and-freeze, api-contract + simplification review lenses, security lens rate-limit +
  destructive-path target validation, speed-it keep-or-revert + attempt ledger, map-it
  Prototype/Task ticket types, compound-learn environment-improvement categories, release.md
  doc-sync unit, sandbox-policy Never-row target validation.

- `pin-it` mission: re-witness and re-pin runtime-mechanics doctrine against the installed Orca
  binary — per-claim receipts, archived refutations for removed claims, substrate-block
  classification; terminals `PINNED` / `PINNED-WITH-PARKED` (from the 2026-09-09 upstream
  adoption audit).
- `floor-it` mission: install a written, numbered, tool-enforced quality bar — frozen
  CONSTRAINTS table, one tool per dimension, prove-fires negative control per gate, GUARD
  diff-watch against bar-lowering; terminals `FLOORED` / `FLOORED-WITH-PARKED`.
- `reshape-it` mission: churn-weighted shallowness inventory → human-confirmed surface →
  mutation-audited characterization net pinned BEFORE any restructure → one module-deepening
  per unit with build-blind review; terminals `RESHAPED` / `RESHAPED-WITH-PARKED`.
- `field-test-it` mission: on-device verification via the Orca emulator skills or a paired
  physical device — baseline, reproduce, fix, re-verify at `head_sha` with a revert negative
  control; terminals `FIELD-PROVEN` / `FIELD-PROVEN-WITH-PARKED`.

**The images are now generated from a committed prompt source, and they answer developer
questions instead of restating the mermaid.** Every banner and diagram under `assets/` is
re-rendered with Nano Banana Pro from the prompts in `assets/diagrams/generator/`, so a stale
picture is a prompt edit and a rerun rather than a redraw. The 21 mission diagrams became
developer-contract cards: what you give it, what it interrupts you for, what you get back, and
where it stops, at 60 words or fewer so the captions survive the guide's embed width; the
pipeline stays in each guide's mermaid block. Nine visuals were added where a question had no
picture: the you-say table that opens the README, the negative-control head-to-head, the install
stack with its three paths and their gate status, the gates as they reach your terminal, the
artifacts a run leaves behind, the mission handoff graph, the proof ladder, the verify-gate
trust boundary, and the mission-identity test. Every diagram ships a light variant behind a
`<picture>` element. ARCHITECTURE.md deliberately carries no image: it counts toward every
mission's activation load, and the validator said so.

**The 2026-09-14 tracker run's supervision lessons are now policy.** One field
run produced a hung reviewer, a wedged verdict worker, and two fenced
coordinator terminals; the recoveries are preserved as `runtime/worker-supervision.md`
(per-dispatch budgets, the stuck-but-alive ladder, transcribe-at-delivery,
fenced-coordinator re-bind). Beside it: `playbooks/mutation-hunt.md`, the
reviewer-side method the run's three review rounds converged on (killer mutants
in scratch clones, forced schedules, vacuity guards, forced residual demos),
and `playbooks/conductor-close.md`, the post-merge evidence closure generalized
from the run's own taskspec. All three compose from clean-sweep's deferred
reads, keeping them out of activation load; the one ARCHITECTURE bullet the
new policy required cost clean-sweep ~100 tokens of headroom (33,800→33,900).

**The supervision ladder's first responses are mechanized (#418).**
`runtime/scripts/watchdog.py` polls worker heartbeats, classifies
OK/SLOW/HUNG/WEDGED, auto-nudges HUNG once, and emits stop-redispatch
RECOMMENDATIONS with JSONL evidence on still-HUNG or WEDGED — the stop and
re-dispatch stay coordinator decisions. Thresholds and rate limits live in
`runtime/watchdog.json` (tunable without code edits); `--dry-run`
classifies with zero side effects. A recorded 2026-09-14 heartbeat trace
ships as the replay fixture.

### Fixed

- Runtime scripts no longer spell the Orca CLI as `orca`: on Linux that name is the GNOME screen
  reader (`orca-ide` is the CLI, per upstream's own resolution stub), so every dispatch from a
  Linux host either hung on the wrong program or failed at `command -v` (#510).
- Five stale hand-typed claims re-stated against live state: the Orca floor (v1.4.215) in the
  README, install, getting-started and distribution pages; the proof-tier sentence; the opening
  of `docs/call-for-runs.md` (every listed mission stands at `doctrine-only`); the 1.0 checklist's
  Gate 1, which grepped for a check that no longer exists (#512).
- The v1.4.215 pin record now carries what the re-pin missed: the schema line moved v41 → v42
  (`orca-dag-semantics.md`), and two post-pin upstream commits — the `dispatch:` → `run:` mail
  redirect with its `recipient_run_bound_redirect` warning, and the `dsh` agent — are logged in
  `orca-pin.md` for the 2026-12-28 re-pin (#508) to witness (#513).
- The Python floor is what the suite proves, not an installer policy: `install.sh` asks for
  ≥ 3.11 (the code needs 3.10; two 3.10-only failures are test-side) instead of 3.13, and the
  docs say so in one sentence (#514).
- The negative-control demo's transcript check no longer depends on stdout/stderr interleaving
  or on the uid: `run.sh` runs the verifier unbuffered, the workflow strips the host-dependent
  custody NOTE lines before diffing, and the recorded transcript and its inventory hash were
  regenerated (#522).
- The tests badge counts what it says — "test functions", which is what `unittest` discovers —
  instead of "test definitions" (#524).

## [0.6.1] - 2026-09-09

plugin.json, marketplace.json, and this heading now agree on 0.6.1 (issue #237).
The alert-on-failure workflow, the completion-run items, and the ops rollback
step.

### Added

- `alert-on-failure` workflow (#213): a failed `validate` run on `main` opens or
  updates an issue labeled `ci-failure`; a `workflow_dispatch` drill files and
  closes a `[drill]` issue so the alert path can be proven without redding
  `main`. `validate` publishes the proof rollup and routing score to its run
  summary; `docs/ops.md` incident step 1 names the issue as the alert. The
  drill on `main` filed and closed #229 on 2026-09-02.
- `docs/runs/TEMPLATE.md` and a per-mission field-proof plan in the run-archive
  index (#212): targets, tiers, terminals, and blockers for the nine
  doctrine-only missions; a tier still advances only through a mission run.

### Changed

- `docs/ops.md` incident step 4 documents the rollback this catalog has
  (`git revert -m 1` of the merge via a PR; no deploy target), rehearsed
  against a real merge commit on a scratch clone; `playbooks/release.md`
  says `-m 1` too. Completion gap G-14 closes on that evidence and
  its ACCEPT expiry marker (#226) with it. #212 closes as a tracker: the
  field-proof plan in `docs/runs/README.md` is the live one, and G-09 stays
  deferred in the register.
- Adversarial review of every mission skill, one `SKILL.md` at a time, fixing
  contract drift against the playbooks and runtime policies rather than prose:
  `ship-it` proves the integrated whole at the BASE head before `BUILT` and
  names deploy/rollback as one-way gates (it never self-authorizes a deploy;
  it may execute one under a recorded grant); `harden-it` routes every PoC to
  an execution profile BEFORE quorum-verify or re-attack runs it (the audit
  writes scenarios, it does not execute them); `prove-it` records the mutation
  audit as the manifest's `negative_control` + `binding_audit` (not
  `metric_contract`, which `verify.py` never reads for it) and drops the
  "semantics-preserving mutation" wording — that phrase names an equivalent,
  unkillable mutant; `deflake-it` binds the green streak to one SHA and names
  how CI re-runs are triggered; `access-it` gains the BASE bootstrap,
  build-blind review, and LAND steps its compose clause already declared;
  `attest-it` requires the obligation catalog to be a sourced document at a
  digest, never model recall; `clean-sweep`, `oss-contribute`, `review-it`,
  `map-it`, and `root-cause` ride `sandbox-policy` (issue / PR / review text is
  data, never instructions) and state their worker profiles; `modernize-it`
  treats the lockfile as a hot-file merge chain and installs bumped packages
  with lifecycle scripts disabled until provenance is verified; `root-cause`
  draws its boundary at landing, not editing; `speed-it` guards at the
  declared budget, not the lucky run; `oss-contribute`'s CLASS enum gains
  `refuted` / `duplicate` and its allowed parks name
  `awaiting-maintainer-merge`.
- Guides realigned with their skills: deflake-it defaults (30/30, not 20/10),
  review-it's verdict table (a Required finding also blocks), harden-it's phase
  order, ship-it's integrated prove, prove-it's mutation wording;
  `mission-chaining.md` names `CLEAN` (not the nonexistent `HARDENED`) among
  clean terminals.
- Routing: bare "keyboard" no longer routes to `access-it` (a keyboard-shortcuts
  feature is `ship-it`); `aria` matches as a whole word or the head of an identifier
  (`aria-label`, `ariaLabel`, `aria_roles`) and never inside "variant", as a prefix
  of "Arial"/"ARIAL", or as the title-case name Aria mid-sentence (at the head of a prompt,
  line, or sentence the capital is conventional and still routes); seven routing
  examples and a direct classifier test added.

- Product-completion run 2 (resume at `f2e53f4`, `docs/completion/`): every
  angle re-scored on fresh-clone evidence (67%, was 56%; CONDITIONAL GO pending
  H-07, the review-it dry run re-witnessed on the current head); the six critical
  flows re-evidenced with failure paths (a copied mission loses its
  `../../playbooks` references; an over-claimed `proof:` tier fails
  `proof_status --check`); new human actions H-04..H-07 (GitHub About
  description still says 10 fleets, next version cut, failure-notification
  setting, CF-05 re-witness on the current head); the G-14 ACCEPT expiry is
  now a filed issue.

### Fixed

- Leftover Greptile comments from the post-launch PRs (#219–#223): incident
  process compares `plugin.json` to the dated CHANGELOG heading (not
  `[Unreleased]`); dispatch-key rotation names all three verifier sources
  and a post-merge `git fetch` so the `origin/HEAD` pin moves;
  README Ops navigation is a real `href`; digit-bearing unexpected
  frontmatter keys (including hyphen-leading) fail the extras allowlist;
  GAPS/`status.json` match the closed G-06..G-08/G-11..G-13 issues.

## [0.6.0] - 2026-09-01

plugin.json, marketplace.json, and this heading now agree on 0.6.0 (issue #209).
Signed dispatch, the #163–#184 sweep leftovers, SECURITY.md, the Python 3.13
pin, product-completion close-out, and the post-launch G-08/G-11/G-12/G-13/G-07
agent slice.

### Added

- Signed dispatch records make a worker's substitution of `{manifest-id, contract-digest, unit-class,
  lighting}` **detectable off-worker** (issue #135, follow-up to #112). The coordinator signs the tuple
  off-worker (`runtime/scripts/dispatch-sign.py`, vendored Ed25519 in `runtime/scripts/ed25519.py`);
  `verify.py` verifies the signature against a supplied public key, binds it to the unit, and rejects a
  substituted or unsigned field. This is a soundness boundary **when the verifying key is trusted —
  i.e. off-worker** (CI/MCP/SDK, or an auditor with the coordinator's real key); the native in-session
  hook stays advisory (no in-session anchor is worker-untamperable, the #112 result). Opt-in; default
  behaviour unchanged. See [docs/verify-gate.md](docs/verify-gate.md#signed-dispatch--making-the-native-path-sound-135).
- `SECURITY.md` disclosure path; `.env.example` lists every `ORCA_*` gate input.
- [docs/ops.md](docs/ops.md): account inventory (GitHub, plugin marketplace,
  greptile, agentskills) and a 3-step incident process (issue #215).
- Index check of public marketplace aggregators (issue #210): GitHub self-host
  and buildwithclaude auto-index are live; official directory, skills.sh, and
  claudemarketplace.net still need [H-02](docs/completion/HUMAN_ACTIONS.md).

### Changed

- CI Python pin `3.x` → `3.13` (catalog gates).
- CI runs ruff 0.16.5 on `E9`/`F63`/`F7`/`F82` (syntax / undefined names)
  only (issue #214). Full rule set is still a policy change.
- Validator and the orphan-protocol test share `explicit_protocol_refs` (issue #216).
  A Related-section backtick no longer keeps a protocol alive; `ship-it` rides
  `mission-chaining` and `review-it` rides `mission-scheduling`.
- Validator allowlists only three extras beyond the agentskills.io spec
  (`proof`, `autonomy`, `proof_evidence`). A fourth top-level field fails
  the catalog (issue #211). skills-ref still reports those extras; that is
  expected, not a migrate-to-metadata prompt.

### Fixed

- Leftover review comments from the #163–#184 sweep PRs: pin discovery cannot
  cheat via local `HEAD`; env pubkey precedes the repo pin; nested schema keys
  are matched as keys not substrings; the trust-boundary assertion is bounded
  to that H2; `ORCA_EXECUTE_NC` is documented as fail-closed; vf-bench ancestry
  is hermetic; the review-leg GREEN half still skips on a shallow clone (the
  fail-closed fetch pin does not — `verify()` keeps aggregating); mutation e2e
  tests spy the review and NC lanes; temp fixtures are cleaned up.
- Validator: a non-UTF-8 or unreadable `SKILL.md` (and the same class of error
  in playbooks/runtime) is a one-item per-file failure instead of aborting the
  catalog (issue #71).

## [0.5.0] - 2026-08-26

Release hygiene: the previous Unreleased block was already on main (issue #42).
plugin.json, marketplace.json, and this heading now agree on 0.5.0.

### Fixed — live docs after E1–E6

- Mission guides' Composes sections now name every protocol their SKILL declares
  (ledger-contract, evidence-manifest, acceptance-review, and the rest that had drifted).
- Human-facing schema (README, concepts, getting-started, ARCHITECTURE) documents the
  intent packet, lighting, and `accountable:` on promotion.
- README proof status includes the 2026-07-17 clean-sweep tracker self-run.
- Research archive index marks snapshots as historical; E1–E6 landed in PR #68.

### Added — Addy August delta (E1–E6)

- Lighting: per-unit `lit` / `dark-eligible` (`gate-classification.md`, ledger row,
  evidence manifest). Default lit; dark-eligible only Lane A + unfakeable oracle.
- Intent packet on the evidence manifest (`goal` · `ruled_out` · `why`); verifier
  checks presence. Distinct from `claim`.
- Autonomy contract on TASK specs (`decompose-dag`, `remediate-finding`).
- `compound-learn` + `attention-budget` composed by the remaining mutating missions.
- Promotion PR names `accountable: <human>` (`release.md`).
- Next self-run must emit the WIP-curve row (`docs/runs/README.md`).

### Added — orchestration-tax adoption (Addy gap analysis)

- `runtime/attention-budget.md`: producer-side WIP caps (default ≤3 builders),
  sort isolated vs judgment-heavy work, scale fleet to verification capacity.
- `playbooks/compound-learn.md`: post-mission REFLECTION.md proposals; human must
  approve every AGENTS.md/GOTCHAS line (never auto-write).
- `liveness-resume.md`: reflection-before-retry + identical-error kill on doctor
  respawns.
- `build-change.md` + `gate-classification.md`: pre-build plan gate for
  irreversibility stop-list units.
- Wired into `ship-it`, `clean-sweep`, `harden-it`; docs in concepts, getting-
  started, ARCHITECTURE, README; research archive under `docs/research/`.

## [0.4.0] - 2026-07-16

Adds an eleventh mission, `oss-contribute`: landing contributions on a repo you
do NOT control. It is `clean-sweep` forked for upstream work, and it is a distinct
mission by the five-part test — the convergence proof is a PR open and internally
reviewed (not a merged SHA), the state machine adds upstream-PR overlap discovery
and an assist/alternative/stand-down decision while dropping the merge step and the
merge-serialization conductor, and `awaiting-maintainer-merge` / `externally-covered`
are normal terminals. Ships with the `upstream-contribution` playbook (fork topology,
overlap check, contribution decision, DCO/CONTRIBUTING etiquette) and enters at
`external-run` proof — a real run against `dodopayments/chimely` (5 PRs, 4 quoted
review-assist comments) is in `docs/runs/`. `validate.py` now holds `oss-contribute`
to the mutating-mission evidence-manifest standard.

`oss-contribute` also gained a post-open PR follow-up loop: a PR is not
fire-and-forget, so the unit stays live (watch, triage each review thread against
the current head, fix valid ones as fix rounds on the same branch, answer every
thread) until merged, closed, or quiet. Adds the `FOLLOWED_UP` ledger flag.

Made the catalog messaging count-agnostic so adding a mission no longer means
rewriting counts across the docs. The README badges now read dynamically (version
from `plugin.json`, mission and test counts from generated `assets/badges/*.json`
via `scripts/gen-badges.py`); the manifest descriptions dropped the count and the
mission enumeration; and `validate.py` gained three guards — a count-lint that
fails on any hardcoded catalog count in the doc surfaces, a keyword check that
every mission is in `plugin.json` keywords, and a badge-freshness check.

## [0.3.0] - 2026-07-13

Syncs the runtime policies with the current Orca `orchestration` and `orca-cli`
skills (an audit against both found drift, including one bug in 0.2.1), and adds
two capabilities the audit surfaced: the full agent roster and scheduled runs.

### Added — agent roster (flags from Orca source, autonomy-correct)

- `spawn_worker.sh` now covers the Orca roster, and the write tiers use each
  agent's fully-autonomous flag — the exact flag Orca appends by default
  (`src/shared/tui-agent-permissions.ts`, cloned and read directly):
  claude `--dangerously-skip-permissions`, codex
  `--dangerously-bypass-approvals-and-sandbox`, gemini `--yolo`, grok
  `--permission-mode bypassPermissions`. This fixes a latent blocking bug: the
  prior `rw` flags (acceptEdits / workspace-write / auto_edit, and a wrong grok
  `--always-approve` from a web source) are the SANDBOXED modes that still
  prompt on shell + network, so a build worker running tests or `npm install`
  would block and defeat the run — the exact failure this project exists to
  avoid. `ro` stays read-only (non-blocking because it cannot mutate); `danger`
  shares `rw`'s flag and adds the ephemeral-sandbox requirement. opencode/droid/
  omp/pi have no Orca autonomous launch flag → `WORKER_CMD`. The old
  claude|codex-only refusal is gone; `WORKER_CMD` generalizes the override to
  any agent; `sandbox-policy.md` carries the full matrix.
- Because `rw` launches a permission-bypass worker, it is fail-closed behind a
  new explicit opt-in `ORCA_COORD_ALLOW_AUTONOMOUS_WRITE=1` (mirroring the danger
  gate) so a bare/accidental spawn never starts a bypass worker silently. The
  safety envelope is the isolated worktree + build-blind review + PR gate +
  testnet/staging rails; `danger` additionally mandates an ephemeral sandbox.

### Added — scheduled runs

- `runtime/mission-scheduling.md`: Orca `automations` run a mission on a cadence
  (nightly clean-sweep, weekday review-it PR sweep). Each is a full unattended
  run — headless autonomy, one-way gates parked not faked, cross-run
  anti-inflation, stops at BASE/report. Wired to review-it and clean-sweep (the
  cleanly-schedulable missions).

### Fixed

- Subtree lineage (0.2.1 bug): a supervised unit's worktree is created with
  `--parent-worktree active`, not by merely omitting `--no-parent` — the latter
  relies on Orca inferring the parent, which only works "when it can"
  (`runtime/dispatch-lifecycle.md`).
- Inbox mechanics: `check --peek` inspects unread WITHOUT consuming (the correct
  tool when an off-type heartbeat is buried); the old note misdescribed `--all`
  and omitted `--peek`.

### Added

- Provenance rule: lifecycle authority is the payload `taskId`+`dispatchId`
  verified against the dispatched pane, never a handle comparison; a
  `worker_done`/`heartbeat` from a different pane is ignored, and
  `terminal_handle_stale` means re-resolve and never dual-send
  (`runtime/liveness-resume.md`).
- Orca-native progress surface: workers update the worktree comment +
  `--workspace-status` at checkpoints, complementing the file ledger.
- `--setup run` on the builder worktree for repos needing setup hooks;
  `task-list --brief` for coordinator DAG sweeps; the composite worktree-id
  form `<repoId>::<worktreePath>`; the Linux `orca`-is-the-screen-reader gotcha
  (use `orca-ide`); `worker_done` auto-completes the task (no manual
  `task-update`); expanded group roster (`@grok`, `@cursor`).

## [0.2.1] - 2026-07-13

Closes the gaps a coverage audit found between the catalog and the original
Orca coordinator prompt library (the two monolithic prompts this repo
decomposed from).

### Changed

- Worktree lineage is now a subtree per unit: a supervised worker's worktree is
  a CHILD of the coordinator (omit `--no-parent`), and its dependent workers
  (reviewer, fix rounds, integrator, bot reconcile) run as fresh terminals
  inside that worktree — so one `WT_CLEAN` tears the whole subtree down at merge
  (`runtime/dispatch-lifecycle.md`).
- The bot-reconcile policy is generalized from Cursor BugBot to ANY PR review
  bot (Greptile, CodeRabbit, …) with a full wait → ingest → reconcile
  discipline: bounded poll with a did-not-run fallback, comment triage folded
  into one change request, dynamic bot-login detection.

### Added

- First-merge spot-check: the run's first merge gets a dispatched verification
  of its shape before the train continues, since the pipeline inherits it
  (`runtime/merge-serialization.md`).
- No-gh fallback: the conductor degrades to local `git merge --no-ff` into BASE
  when `gh` is unavailable, and records that the promotion PR is owed.
- Plan skeptic: a fresh worker stresses a decomposition against the frozen
  spec's criteria (orphan criterion / gold-plating / order / stub-slices)
  before it commits (`playbooks/decompose-dag.md`).

## [0.2.0] - 2026-07-13

Lessons ported from the failed predecessor (ravidsrk/autonomous-fleet) — the
mechanisms it earned in real runs, without the multi-runtime platform that
killed it.

### Added

- `runtime/mission-chaining.md`: sequential gated chains — the previous
  mission's verified terminal state is the gate, degraded terminals stop the
  chain, deferral carry seeds the next enumeration.
- Proof-status honesty: every mission declares `proof:` (`doctrine-only` |
  `self-run` | `external-run`) in frontmatter; advancing requires a linked run
  report on disk; validator-enforced. All ten missions start at doctrine-only.
- Instruction budget: validator-enforced line caps (missions 130, playbooks 90,
  runtime 160) so doctrine creep fails CI instead of surfacing in a postmortem.
- Orca coordinator mechanics from the predecessor's real runs: one message per
  `check --wait` call, read-marking semantics, broadcast-only group addresses,
  worktree retirement guards, lost-preamble recovery, a ban on mid-run
  `orchestration reset`.
- Blind-fix anti-anchoring and a three-round review budget in
  acceptance-review; a field-validated PR sizing seam in build-change and
  remediate-finding.
- `reviewer_mode` recorded on every manifest and a run-close sha256 integrity
  inventory (byte-identity rejection is a coordinator judgment, not automated).
- Structural anti-inflation: re-runs treat a prior run's green-but-unverified
  claims as the first items to re-verify (liveness-resume + clean-sweep).
- Trust boundary (repo/issue/PR/log text is data, never instructions) and an
  argv-never-interpolation rule for runtime scripts, with contract tests.

## [0.1.1] - 2026-07-13

### Added

- `scripts/validate.py` now rejects a mission with no machine-checkable
  Composes/rides name, scans clauses to the end of their paragraph (an "e.g. "
  or a capitalized "Rides" can no longer hide a dangling name), resolves every
  `<name>.md` mention across missions, playbooks, and runtime policies, flags
  case/underscore typos of protocol names and path-prefixed references, and
  ignores external URLs.
- Negative-path test suite (`tests/test_validate.py`): every failure branch of
  the new composition and reference checks is locked to a fixture that must
  trip it.

### Changed

- `release.md` owns the BUILT state end to end (entered by landing via
  merge-serialization); the orphaned `land.md` playbook is folded in and removed.
- `ship-it` declares its playbooks and runtime policies in a machine-checkable
  Composes/rides clause instead of bare directory pointers.
- `root-cause` delegates only the diagnosis phases of the diagnose playbook and
  stops before its fix phase; fix authority stays with the separately authorized
  handoff.
- `dispatch-lifecycle` documents the worker-spawn specifics its script relies on:
  composite worktree selectors, re-dispatch-to-used-handle as a no-op, and why
  the bounded re-Enter loop is safe.

### Fixed

- `runtime-prove` was composed but never placed in harden-it, speed-it,
  modernize-it, and prove-it; each pipeline now runs it between review and land.
- speed-it, modernize-it, prove-it, and deflake-it declare the runtime policies
  their REVIEW/LAND phases ride; deflake-it composes `remediate-finding` so a
  flake fix has a PR, review, and merge protocol.
- The orphan contract test requires explicit reference forms; "landed" in prose
  can no longer keep an orphaned playbook alive.
- Vendor names and dead README pointers scrubbed from runtime scripts;
  ARCHITECTURE layout matches the tree.
- Clarity: `{{DETECT_RUNS}}` gets a default (20), the exploit sandbox is named
  `sandbox-policy` consistently in harden-it, observe.md's depth heading no
  longer points at a definition release.md never had, and review-it's
  test-adequacy axis is marked as static reasoning for read-only workers.

## [0.1.0] - 2026-07-13

### Added

- Initial catalog: 10 outcome-named missions, callable playbooks, runtime
  policies and scripts, the agentskills.io validator, and architecture contract
  tests.
