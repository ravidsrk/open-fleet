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
| Installed version | **v1.4.239** (installed Orca.app + CLI 1.4.239, macOS arm64; tag `v1.4.239` source-delta re-witness from v1.4.238; live 1.4.239 receipts; deeper orchestration receipts carried from the 1.4.224 macOS + Linux `orca-ide serve` witness) |
| Build commit | `47f77cf7018ebc0d046b82c6dde31cf704909162` (tag `v1.4.239` target commit, "release: v1.4.239"; upstream builds from release branches, so the tag IS the release source) |
| Witnessed | 2026-10-26 (`source`: source-delta re-witness `v1.4.238..v1.4.239` across specs, guides, orchestration contracts and every cited upstream file, plus live 1.4.239 receipts: the CLI capture and the #680 ro/claude worker witness) |
| Upstream HEAD then | `35af10dded` (main, 2026-10-26; newest tag and latest release v1.4.241) |
| Run record | docs/runs/2026-10-26-pin-it-239.md (drift tables) + docs/runs/2026-10-26-pin-it-239/ (live capture, diffs, delta inventory D239-1…6) + docs/runs/2026-10-26-review-it-orca-ro-680.md (the live worker witness) + docs/runs/2026-10-12-pin-it-224/ (older live receipts, carried) |
| Prior pin | v1.4.238 `e6f7fba5` (2026-10-24, docs/runs/2026-10-24-pin-it-238.md) |
| Verdict | **PINNED-WITH-PARKED** — `sandbox-policy.md`'s host modes patched for the stored permission choice; stale citations re-anchored; additive v1.4.239 surfaces noted (`connector`, helper workers under SUB-DISPATCH, the `ask --timeout-ms` cap); the ro lane's no-inject fallback (#680) live-witnessed |

## What moved since v1.4.224 (diff summary)

Method: DELTA, not re-derivation — at v1.4.224 the guides, help root, and agent-context were
re-dumped from the installed binary and replayed live on the Linux serve substrate (D224-1…10,
`docs/runs/2026-10-12-pin-it-224/`); at v1.4.229 and v1.4.238 the tag-range source delta was
audited line by line (D229-1…7, D238-1…10, each run's directory).

- **v1.4.239 delta (D239):** a terminal launch's permission is a stored choice per agent (`own`,
  `ask`, `accept-edits`, `auto`, `full-access`) whose flag precedes the user's Arguments —
  `sandbox-policy.md` names it, and `spawn_worker.sh` still exits 5 on anything but the rw flag;
  `dispatch --inject` cannot see a native Claude Code install (D239-2; #680's no-inject fallback,
  live-witnessed); helper workers under SUB-DISPATCH run in the worker's own Run (off by
  default: depth 1); `ask --timeout-ms` is capped at 1800000; `connector` (6 commands). Schema
  v43, the dispatch and agent-presence code and the orchestration CLI spec's paths are unchanged.
- **v1.4.238 delta (D238):** a global Auto permission switch (`AUTO_TUI_AGENT_ARGS`: claude
  `--permission-mode auto`, codex `--approve-for-me`) — `sandbox-policy.md` names it and
  `spawn_worker.sh` refuses it (exit 5, test-pinned); `--host`/`--project` take the names
  `host list`/`project list` print (`mission-scheduling.md`); `--surface chat|terminal` and
  per-agent chat defaults (`dispatch-lifecycle.md`); `terminal set-pane-title` (parked in
  `terminal_ops.py`); `linear comment edit|delete`; `speech openai-key`. Schema v43, the
  orchestration guides, the orchestration CLI spec and the YOLO map are unchanged.
- **v1.4.229 delta (D229-1…7, PATCHED then):** `orca jira`, `agent launch`, `reference`, `serve`
  OS containment env vars, `task_not_startable.failureCount`, `automations runs` paging.
- **v1.4.224 live receipts carried forward (`dispatch-probes.txt`):** conditional `--dispatch-capability`
  (D224-1); OMP/OpenCode `--model` (D224-3/9); task lifecycle (`task-update --result <text>`,
  `worker_identity_changed`, `consumer_fenced`, `worker-abandon`, `terminal stop` EXECUTES,
  `worker-list` projection, `no_active_sender_terminal`, `recipient_run_bound_redirect`, `vm recipe doctor`
  verdict shapes); and Schema v43 (`orca_session_id:<id>` respell, unchanged through v1.4.238).
- **Still parked:** `caller.orcaSessionId` (D224-6), `P27` legacy-takeover live replay, agent-owned
  abandon + send-side `consumer_fenced`, live replay of `orca jira` / `reference` / `agent launch`
  and of v1.4.238's `--surface` receipts, and a live `launch.effective` under each stored
  permission choice. A 1.4.239 binary capture now exists (`receipts-live-2026-10-26`).

## Noted since the pin (inherited by the next re-pin)

- PATH ran 1.4.239 at the v1.4.239 witness. Upstream was already at v1.4.241, two patches
  ahead, below the probe's ten-patch trigger.
- The v1.4.238 re-witness ran while the #606 ablation was registered but unrun; the bump
  re-registered it (version 2) because four of the docs it edits are in that payload.

Both 2026-09-28 compass points (#513) shipped and were dispositioned at v1.4.224:
`recipient_run_bound_redirect` (v1.4.217) replayed live — `dispatch-lifecycle.md`
addressing now names it; `dsh` (v1.4.218) is upstream-available and deliberately not on
the `spawn_worker.sh` roster (both zero-diff through v1.4.238). Notes carried:

- The Linux witness's first `serve` logged `[agent-state-rules] download failed: HTTP 404`
  — witness-first-run noise to watch, not a doctrine claim (relates to #526).
- `caller.orcaSessionId` (D224-6) waits on a structured agent session in the witness VM
  (an agent account signed in there) — the same substrate the self-run programs need.
- `ORCA_CHAT_VISUALS_DIR` was renamed to `ORCA_CHAT_SCRATCH_DIR` in v1.4.229 (`orca-chat-visuals`);
  no fleet script references it.
- The weekly probe (`"$OPEN_FLEET_ROOT/runtime/scripts/upstream_probe.py"`, `.github/workflows/upstream-drift.yml`,
  #516) files an `upstream-drift` issue on a new minor, ten patches behind, or — `review-date`,
  #508 — on or after `pins.json` `orca.next_review`, so no standing issue carries the cadence.

## Re-pin cadence + owner

A re-pin fires on whichever comes first:

1. Each Orca **minor** release (patch bumps ride until ten pile up, or a drift NOTE or guide diff says otherwise).
2. **Quarterly** at minimum — the date trigger keeps a quiet upstream honest.
3. A `SPAWN=NOTE … run pin-it` sighting in the field, or any dispatch-doc drift report.

Owner: the **pin-it** mission (its coordinator runs the loop; the weekly probe files the issue).
Next trigger: **2027-01-26** (`pins.json` `orca.next_review`, a quarter after this witness) or
the next minor / ten patches behind / drift sighting, whichever first. The weekly probe files
triggers 1 and 2 itself — no issue to open; the successor run inherits the park register in
docs/runs/2026-10-26-pin-it-239.md.

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
5. Refresh the park register, set the next quarterly date in `pins.json` `orca.next_review`
   and the Next trigger line together (the weekly probe files it — no issue to open),
   regenerate badges (`scripts/gen-badges.py`), and land with `scripts/validate.py` + `tests/` green.

## Pack pin bumps carry a rug-pull review (#559)

The worker-pack pins (gstack, addyosmani, mattpocock) are supply-chain admissions:
their instructions are what a worker obeys. A bump therefore lands with its diff
review, or not at all — `tests/test_pins.py` enforces it.

1. Clone the pack (blobless is fine); run
   `"$OPEN_FLEET_ROOT/runtime/scripts/pin_review.py" --repo <clone> --pack <key> --from <pinned> --to <new>`
   into `docs/research/pin-reviews/<key>-<new-commit-as-pinned>.md`.
2. Read the instruction and permission-surface changes it lists (hooks line-by-line —
   they execute inside the worker), replace the `UNREVIEWED` verdict, fill the notes.
3. Land pin + artifact together. A permission-surface widening you cannot explain is
   a refusal, not a note: keep the old pin and file the finding.

The orca pin is exempt from this artifact — the re-pin procedure above is its
(deeper) equivalent.

## 2026-09-26 correction — `terminal stop` was never witnessed removed (D1/D10)

A "What moved" line since rewritten claimed `terminal stop` removed at v1.4.209. That overstated
what the run witnessed: source at the build commit keeps it as a hidden (`core.ts:241`) deprecated
(`core.ts:242,246`) spec with its handler still present (`handlers/terminal.ts:137-142`) — same at
HEAD 4cafa50e. `dispatch-lifecycle.md` now hedges accordingly. Live re-probe parked for the next
pin-it with a live terminal: `orca terminal stop --worktree <selector> --json` (does it execute
or refuse?) plus `orca terminal --help` (does `stop` stay unlisted?).

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
