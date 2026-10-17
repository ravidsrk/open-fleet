# Runtime pin — which Orca this doctrine was witnessed against

The fleet's runtime mechanics (`dispatch-lifecycle`, `liveness-resume`, `orca-dag-semantics`,
`merge-serialization`, `gate-classification`, `sandbox-policy`, `mission-scheduling`,
`worker-supervision`, and the scripts that touch the binary) are re-witnessed against the
INSTALLED Orca binary on every pin-it run — never trusted from memory or release notes. This
file is the human-readable pin record: what was witnessed, what moved, when the next re-pin
fires, and who owns it. The machine-readable pin is `pins.json` (same directory):
`spawn_worker.sh` NOTEs when the binary on PATH differs from it, and `tests/test_pins.py`
holds its shape. The two never disagree — a run updates both or neither.

## Current pin

| Field | Value |
|---|---|
| Upstream | `stablyai/orca` (`https://github.com/stablyai/orca`) |
| Installed version | **v1.4.229** (tag `v1.4.229` source-delta re-witness from v1.4.224; live orchestration receipts carried from installed 1.4.224 macOS + Linux `orca-ide serve` witness) |
| Build commit | `a0cd1644f320f1327f7495650a816111b495f3cd` (tag `v1.4.229` target commit, "release: v1.4.229"; upstream builds from release branches, so the tag IS the release source) |
| Witnessed | 2026-10-17 (`source`: source-delta re-witness `v1.4.224..v1.4.229` across `skills/`, `skill-guides/`, `src/cli/specs/`, and `src/shared/`, plus carried 2026-10-13 live Linux/macOS receipts for unchanged orchestration paths) |
| Upstream HEAD then | `38131048b1` (main, pulled 2026-10-17; newest tag + latest release both v1.4.229, 2026-10-17) |
| Run record | docs/runs/2026-10-17-pin-it-229.md (ledger + park register) + docs/runs/2026-10-17-pin-it-229/ (delta inventory D229-1…7) + docs/runs/2026-10-12-pin-it-224/ (live receipts) |
| Prior pin | v1.4.224 `2bb20586` (2026-10-13, docs/runs/2026-10-12-pin-it-224.md) |
| Verdict | **PINNED-WITH-PARKED** — stale "no Jira CLI" claim in `linear-enumeration.md` patched; five additive v1.4.229 surfaces folded in (`orca jira`, `orca agent launch`, `orca reference`, `orca serve` OS containment env vars, `task_not_startable.failureCount`, `automations runs` paging); live v1.4.224 receipts carried for unchanged orchestration paths |

## What moved since v1.4.215 & v1.4.224 (diff summary)

Method: DELTA, not re-derivation — at v1.4.224 the guides, help root, and agent-context were
re-dumped from the installed binary and replayed live on the Linux serve substrate (D224-1…10,
`docs/runs/2026-10-12-pin-it-224/`); at v1.4.229 (`a0cd1644`) the 5-release source delta
(`v1.4.224..v1.4.229`) was audited line-by-line (D229-1…7, `docs/runs/2026-10-17-pin-it-229/`).

- **v1.4.229 delta (D229-1…7, PATCHED):**
  1. **First-class `orca jira` CLI (19 commands) + `orca-jira` / `jira-tickets` skills (D229-1):**
     `linear-enumeration.md` previously claimed no Jira CLI existed; now teaches `orca jira list` /
     `jira search <jql> --site <id> --json`, named workflow transitions (`jira status list/set`),
     single-attempt write verification, and JQL `--limit` bounding.
  2. **`orca agent launch` + `worktree create --agent` flags (D229-2):** starts an agent in an
     existing workspace (structured chat or terminal per settings) with `--model`, `--effort`,
     `--retry-launch <operationId>`, and `--reference` / `--reference-site` on `worktree create`.
  3. **`orca reference list|add|remove|find` (D229-3):** workspace link management and cross-workspace
     agent/liveness lookup (`linked`, `liveness`, `terminal`, `mailbox`).
  4. **`orca serve --supervise`, `serve service`, `terminal-daemon`, and OS terminal containment (D229-4):**
     `ORCA_TERMINAL_PROCESS_CEILING` (≥64, Linux systemd scope / Windows Job object) and
     `ORCA_TERMINAL_MEMORY_MAX` / `ORCA_TERMINAL_MEMORY_SWAP_MAX` (≥256M, Linux cgroup OOM containment)
     folded into `sandbox-policy.md` and `threat-model.md`.
  5. **Circuit-breaker `task_not_startable.failureCount` + failed `worker-start` cleanup (D229-5):**
     failed `worker-start` attempts count across `--retry-of` (a worker's own `failed` report does not),
     and a `--retry-of` replacement of a `failed` worker releases the terminal it owned (`dispatch-lifecycle.md`).
  6. **`orca automations runs --limit --cursor` + sleeping finished automation terminals (D229-6):**
     folded into `mission-scheduling.md`.
- **v1.4.224 live receipts carried forward (`dispatch-probes.txt`):** conditional `--dispatch-capability`
  (D224-1); OMP/OpenCode `--model` (D224-3/9); task lifecycle (`task-update --result <text>`,
  `worker_identity_changed`, `consumer_fenced`, `worker-abandon`, `terminal stop` EXECUTES,
  `worker-list` projection, `no_active_sender_terminal`, `recipient_run_bound_redirect`, `vm recipe doctor`
  verdict shapes); and Schema v43 (`orca_session_id:<id>` respell, unchanged through v1.4.229).
- **Still parked:** `caller.orcaSessionId` (D224-6), `P27` legacy-takeover live replay, agent-owned
  abandon + send-side `consumer_fenced`, and live CLI replay of the new v1.4.229 `orca jira` /
  `reference` / `agent launch` verbs against a connected Jira site.

## Noted since the pin (inherited by the next re-pin)

Both 2026-09-28 compass points (#513) shipped and were dispositioned at v1.4.224:
`recipient_run_bound_redirect` (v1.4.217) replayed live — `dispatch-lifecycle.md`
addressing now names it; `dsh` (v1.4.218) is upstream-available and deliberately not on
the `spawn_worker.sh` roster. Notes carried at v1.4.229:

- The Linux witness's first `serve` logged `[agent-state-rules] download failed: HTTP 404`
  — witness-first-run noise to watch, not a doctrine claim (relates to #526).
- `caller.orcaSessionId` (D224-6) waits on a structured agent session in the witness VM
  (an agent account signed in there) — the same substrate the self-run programs need.
- `ORCA_CHAT_VISUALS_DIR` was renamed to `ORCA_CHAT_SCRATCH_DIR` in v1.4.229 (`orca-chat-visuals`);
  no fleet script references it.
- A weekly probe (`runtime/scripts/upstream_probe.py`, `.github/workflows/upstream-drift.yml`,
  #516) files an `upstream-drift` issue when a new minor lands or the pin falls ten patches
  behind, so the date trigger below is no longer the only thing keeping a quiet upstream honest.

## Re-pin cadence + owner

A re-pin fires on whichever comes first:

1. Each Orca **minor** release (patch bumps ride unless a drift NOTE or guide diff says otherwise).
2. **Quarterly** at minimum — the date trigger keeps a quiet upstream honest.
3. A `SPAWN=NOTE … run pin-it` sighting in the field, or any dispatch-doc drift report.

Owner: the **pin-it** mission (its coordinator runs the loop; the maintainer files the issue).
Next trigger: **2026-12-28** (the standing quarterly date, kept) or the next minor / drift
sighting, whichever first — the successor run inherits this run's park register
(docs/runs/2026-10-17-pin-it-229.md) and carries #508 forward.

## How to re-pin (so a stranger can reproduce the diff)

1. Resolve the oracle: `orca --version`, the app's `orca-local-build.json` commit, upstream
   HEAD (`git ls-remote https://github.com/stablyai/orca.git HEAD`).
2. Freeze a run dir `docs/runs/<date>-pin-it-<issue>/`; archive `orca skills get
   <orchestration|orca-cli> --references` plus every `--reference`, and diff against the
   prior run's `guides/`.
3. Re-witness: replay every CLI-shape claim against `orca agent-context --json` and
   `--help`; run every read-only probe that needs no sender terminal; re-read cited source
   anchors at the build commit. Sender-bound mutations need a live Orca terminal with full
   teardown — without one, PARK them with the exact probe, never reclassify.
4. Tabulate the drift table (one row per policy + per script entry point, every row a
   verdict), fix drift in place, update this file and `pins.json` together.
5. Refresh the park register, file the next dated re-pin issue, regenerate badges
   (`scripts/gen-badges.py`), and land with `scripts/validate.py` + `tests/` green.

## Pack pin bumps carry a rug-pull review (#559)

The worker-pack pins (gstack, addyosmani, mattpocock) are supply-chain admissions:
their instructions are what a worker obeys. A bump therefore lands with its diff
review, or not at all — `tests/test_pins.py` enforces it.

1. Clone the pack (blobless is fine); run
   `runtime/scripts/pin_review.py --repo <clone> --pack <key> --from <pinned> --to <new>`
   into `docs/research/pin-reviews/<key>-<new-commit-as-pinned>.md`.
2. Read the instruction and permission-surface changes it lists (hooks line-by-line —
   they execute inside the worker), replace the `UNREVIEWED` verdict, fill the notes.
3. Land pin + artifact together. A permission-surface widening you cannot explain is
   a refusal, not a note: keep the old pin and file the finding.

The orca pin is exempt from this artifact — the re-pin procedure above is its
(deeper) equivalent.

## 2026-09-26 correction — `terminal stop` was never witnessed removed (D1/D10)

The "What moved" line above claims `terminal stop` removed at v1.4.209. That overstates what the
run witnessed: source at the build commit keeps it as a hidden (`core.ts:241`) deprecated
(`core.ts:242,246`) spec with its handler still present (`handlers/terminal.ts:137-142`) — same at
HEAD 4cafa50e. `dispatch-lifecycle.md` now hedges accordingly. Live re-probe parked for the next
pin-it with a live terminal: `orca terminal stop --worktree <selector> --json` (does it execute
or refuse?) plus `orca terminal --help` (does `stop` stay unlisted?). History above untouched.

2026-09-28 resolution (this re-pin): spec + handler confirmed present at the v1.4.215 release
sources (`core.ts:240`, hidden + deprecated; `handlers/terminal.ts:137`); `stop` stays unlisted
in `terminal --help` (terminal-help-1.4.215.txt) — the listing half is answered. The
execute-or-refuse half re-parks: the app was not running, so the probe returned
`runtime_unavailable` (substrate, not mechanism evidence).

2026-10-13 resolution (v1.4.224 re-pin): EXECUTES. On the Linux serve substrate,
`orca-ide terminal stop --worktree path:/tmp/probe-repo --json` returned `{"stopped": 5}`
(and 3 on the second sweep) and `terminal list` came back empty — the hidden deprecated
verb works and stops every terminal in the worktree. Doctrine keeps `terminal close` as
the canonical teardown; `stop` is recorded as a working blunt instrument. D1/D10 closed.
