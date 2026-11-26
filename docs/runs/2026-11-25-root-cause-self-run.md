# Run report — root-cause self-run, 2026-11-25

RUN: mission=root-cause tier=self-run inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439 manifest=docs/runs/2026-11-25-root-cause-selfrun/manifest.json verifier=GREEN

Self-run of `root-cause` (planning / diagnosis-only class; zero production or test code modified) against this catalog's `runtime/scripts/spawn_identity.py` false-cap failure in `tests/test_spawn_worker.py` under Linux `/proc` `hidepid=invisible`. Built a deterministic single-variable A/B reproduction BEFORE theorizing, checked prior art (`0` matches in `docs/runs/`), ranked and falsified rivals H2–H4 with literal self-contained commands, demonstrated surviving root cause H1 (`spawn_identity.py:474` → `:196`), iterated through three independent build-blind reviews (`R1 NO-GO` catching a real W4-04 transitive bypass → `R2 NO-GO` enforcing literal probe commands → `R3 GO`), emitted a strictly path-free `agent-brief` handoff, and verified **GREEN** via `verify.py --unit-class planning`.

| Field | Value |
|---|---|
| Mission | `root-cause` — SKILL unchanged; zero production or test code modified |
| Tier claimed | `self-run` (against this catalog) |
| Target | `tests/test_spawn_worker.py` spurious `ro` cap (`SPAWN=NOTE ... (W4-04)`) on Linux `/proc` `hidepid=invisible` hosts |
| Fixed point | Subject code @ `cfa3bd63f78df5f0e5e7ee66817ba466d860340b` (unchanged since `4b2e99e5`); pure-prose planning range `3601423ed8a4307e23f7ecf8a2741514246f514f..071256452948b552e287450a419765f7a1c8b812` (`ledger.md` only); contract `docs/runs/2026-11-25-root-cause-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6` (`sha256:299958656074d3c6e296c4b662c29ad7bbb785b1f865923356c2281c6316602c`) |
| Reviewer | Three independent fresh-context build-blind `research` subagents (`same-vendor-fresh`): Round 1 **NO-GO** (`review-r1.txt`) → Round 2 **NO-GO** (`review-r2.txt`) → Round 3 **GO** (`review.txt`) |
| Substrate note | Executed in AQ Linux container (`proc /proc proc rw,relatime,gid=987,hidepid=invisible 0 0`); verified via repo-native `evidence-run.py` + `verify.py --unit-class planning` |

## Terminal state

**DIAGNOSED-WITH-HANDOFF** — surviving root cause H1 demonstrated empirically with A/B single-variable proof and exact verbatim source-seam quotes (`diagnosis-evidence.md`); rivals H2–H4 falsified with literal re-runnable commands (`falsification-probes.txt`); zero production/test files touched; durable path-free `agent-brief` archived in `handoff-brief.md` specifying the mathematically sound transitive shared-hidden-parent invariant across both active and UID-home registries plus 4 fail-closed negative controls for a separately authorized `lit`-reviewed fix mission.

## Convergence proof

1. **Red-capable reproduction BEFORE theory (`repro-red.txt`):** `[RED]` under `PR_SET_DUMPABLE=0` hidden supervisor ancestor deterministically fails `tests.test_spawn_worker.TestUnknownIsNeverAbsent.test_a_response_that_does_not_parse_whole_registers_what_it_names` (`exit_code: 1`, `AssertionError: "parent profile 'rw'" not found`); `[CONTROL A]` on the exact same commit without a hidden supervisor `> 1` passes (`OK`, `exit_code: 0`).
2. **Prior-art check + ranked falsification (`falsification-probes.txt`):** All 6 literal commands independently re-executed by the Round 3 reviewer (`exit_code: 0` each) falsifying H2 (`own_proc`), H3 (`python3 -I` CLI / `setsid` / `Registry`), and H4 (`_uids`) while demonstrating H1 (`whoami(empty_reg)` OK → `whoami(nonempty_live_root_reg)` raises `Unknown: ancestor 546338 of 546371 cannot be read`).
3. **Diagnosis-only boundary + durable path-free handoff (`handoff-brief.md`):** Zero production or test code modified; `handoff-brief.md` conforms strictly to `playbooks/agent-brief.md` (zero file paths, zero line numbers), verified across all three isolated axes in Round 3 **GO** (`review.txt`).

## Verifier outcome (recorded exactly)

Invocation recorded through `evidence-run.py` on clean committed tree `50fc0d1d`:

`python3 runtime/scripts/evidence-run.py --label verifier --manifest docs/runs/2026-11-25-root-cause-selfrun/manifest.json --artifact docs/runs/2026-11-25-root-cause-selfrun/verifier.txt -- python3 runtime/scripts/verify.py --manifest docs/runs/2026-11-25-root-cause-selfrun/manifest.json --contract-source docs/runs/2026-11-25-root-cause-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6 --contract-digest sha256:299958656074d3c6e296c4b662c29ad7bbb785b1f865923356c2281c6316602c --unit-class planning`

Output (verbatim, exit 0, retained in `verifier.txt`):

```
NOTE: redaction: gitleaks at /home/aq-users/mDn3vRscxATUnCmKRdQLXELIVrl1/.local/bin/gitleaks is worker-writable — it can only add hits above the built-in floor, so it is consulted and recorded (h409 R2)
NOTE: --base not given — ancestry check skipped (pre-merge/offline)
NOTE: planning (unsupervised) — claimed with no signed dispatch record. base_sha..head_sha changes prose (docs) only, so the class is consistent with the change, but nothing off-worker authorized it (#310)
verify: OK — all required checks passed
```

## WIP-curve protocol row (mutating self-runs)

Inapplicable: `root-cause` is a planning / diagnosis-only mission (`evidence-manifest.md` §3) with zero code mutations (`builders=0 reviewers=1`).

## Deviations and lessons (recorded, not hidden)

- L1 (security win from build-blind review): Round 1's independent reviewer caught a real W4-04 privilege-escalation bypass in the initial `FIX-AC2` handoff proposal (`ro` root `R` → hidden non-dumpable/setuid intermediate `S` → child `C` escaping uncapped) and forced replacement with the sound transitive shared-hidden-parent invariant across both `reg` and `uid_reg` for live roots and live hosts, plus 4 explicit fail-closed negative controls.
- L2 (evidence discipline): Round 2's independent reviewer caught paraphrased shell commands in `falsification-probes.txt`, proving that every archived probe must be a literal, copy-paste-runnable command that emits its exact verbatim stdout.

## Run-close integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `docs/runs/2026-11-25-root-cause-selfrun/contract.json` | `299958656074d3c6e296c4b662c29ad7bbb785b1f865923356c2281c6316602c` | coordinator frozen contract 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/diagnosis-evidence.md` | `05c6cb4a552c6e12f76ea9975f616a65da833555f3a682404602497c942feba3` | source-bound diagnosis quotes 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/falsification-probes.txt` | `6e7b122f5b3907eec473e05c263490415f8da1cde208548f73cb7f05c253f335` | 6 literal self-contained probes 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/handoff-brief.md` | `04355a47731080ab3d8f3de83ec7950ca681f8c5e584d82da69483c9853eea44` | path-free durable agent-brief 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/ledger.md` | `aabf2e725c086be6ecf136f300479b082ef76119c0ddd6bebba824c987d34bd1` | diagnosis ledger (pure-prose range) 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/manifest.json` | `94f93821f379929d3426062a9102ff23c5ed41ba36c76441d99eef239da8f038` | evidence-run.py + manifest assembly 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/repro-red.txt` | `7c5b1bbb96cd2f6be8e2345b254d1b1eee8dcfdc1df2fa9142f6220d5aa95d93` | deterministic A/B hidepid reproduction 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/review-r1.txt` | `fb85037b38c72018e482a9f750f3fd212e09215478e8f3ddc6afc981f995e047` | independent build-blind reviewer (Round 1 NO-GO) 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/review-r2.txt` | `8af8756dfe22bfd3457755392e5183de1d8054842cfa845f290674080fad9aa6` | independent build-blind reviewer (Round 2 NO-GO) 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/review.txt` | `2f67d7069eb88c35162e52f196c35ff15b31ebe0b9e7a5440ebd1eee814d9f2b` | independent build-blind reviewer (Round 3 GO) 2026-11-25 |
| `docs/runs/2026-11-25-root-cause-selfrun/verifier.txt` | `8d0b19f13ddb9a3cfdb92d8d75b364bd91d60716a8a51bc3b64ef022fbb2cfdb` | evidence-run.py verify.py GREEN 2026-11-25 |
