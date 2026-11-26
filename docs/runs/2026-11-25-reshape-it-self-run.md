# Run report — reshape-it self-run, 2026-11-25

RUN: mission=reshape-it tier=self-run inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439 manifest=docs/runs/2026-11-25-reshape-it-selfrun/manifest.json verifier=GREEN waves=1

Self-run of `reshape-it` against this catalog (`runtime/scripts/verify.py`, seam RV-D3): churn-weighted SCAN (`CHURN(90d)=156`, `WIDTH=91`, `DEPTH=5228`), pre-deepening RV-C3 characterization net pinned at `6b8c2af3`, deepening extraction of the 7 unified-diff and hunk-binding helpers into hashed sibling `runtime/scripts/_verify_diff.py` at `4ad16df4` (`WIDTH` 91 → 84, `DEPTH` 5228 → 5036), build-blind independent review **GO** (Round 1 of 3), VF-Bench 0/53 false-done / 0/19 false-reject, and `verify.py --execute-nc` **GREEN**.

| Field | Value |
|---|---|
| Mission | `reshape-it` — SKILL unchanged by this unit |
| Tier claimed | `self-run` (against this catalog) |
| Target | `runtime/scripts/verify.py` unified-diff & hunk-binding seam → `runtime/scripts/_verify_diff.py` |
| Fixed point | `base_sha=6b8c2af3968482b35ec30b892411b8b6a435f3c5` · `head_sha=4ad16df406c6df3bb2d13f0037ec274802666b61` · contract `docs/runs/2026-11-25-reshape-it-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6` (`sha256:37d6f05a80f4775abbf74535c5ce628c88de4890f0037ed75880dc4ebfaee799`) |
| Reviewer | Independent build-blind `research` subagent (`same-vendor-fresh`, Round 1 GO, `review.txt`) |
| Substrate note | Executed in AQ Linux worktree (standalone `posix` / `open-fleet` harness without Orca desktop app installed); all verification executed via repo-native `evidence-run.py` + `verify.py --execute-nc` |

## Terminal state

**RESHAPED** — confirmed target seam RV-D3 deepened with `WIDTH` shrunk from `91` to `84` (`-7` top-level symbols, `-192` lines in `verify.py`), pre-pinned RV-C3 characterization net green before and after (`6/6 OK`), full carve-out negative-control pair verified, and build-blind review **GO**.

## Convergence proof

1. **Before/after interface-surface measurement:** `grep -cE '^(def |class |async def |[A-Z_]+ =)' runtime/scripts/verify.py` dropped from `91` (`6b8c2af3`) to `84` (`4ad16df4`), pinned in `tests/test_reshape_width_verify.py` (`PINNED_WIDTH = 84`).
2. **Carve-out negative-control pair:**
   - **(a) Pinned mutant still KILLED at `head_sha`:** Hand mutant disabling `_bind_hunks_to_change` overlap check (`runtime/scripts/_verify_diff.py:163`, `negctrl.txt`) executed live by `verify.py --execute-nc` → exit 1 (`AssertionError`), clean `head_sha` exits 0 before AND after.
   - **(b) Revert enlarges interface measurement:** `revert-width-check.txt` restores `verify.py` from `6b8c2af3` and re-measures `WIDTH=91` (`+7` symbols, `+192` lines).
3. **Toolchain & bundle parity:** `_verify_diff.py` registered across `verify.py`, `run_report.py`, `dispatch-sign.py`, `scripts/bundle.py`, and `tests/test_run_report.py`; 973 verifier/toolchain tests + VF-Bench gate (`0/53` false-done, `0/19` false-reject) passed.
4. **Build-blind review:** Independent Round 1 review (`review.txt`) checked deletion test, W3-01 / `importlib` loading, spec fidelity, and 5/5 independent mutation kills → **GO** (0 Critical, 0 Required).

## Verifier outcome (recorded exactly)

Invocation recorded through `evidence-run.py` on clean committed tree `1e0eb50e`:

`python3 runtime/scripts/evidence-run.py --label verifier --manifest docs/runs/2026-11-25-reshape-it-selfrun/manifest.json --artifact docs/runs/2026-11-25-reshape-it-selfrun/verifier.txt -- python3 runtime/scripts/verify.py --manifest docs/runs/2026-11-25-reshape-it-selfrun/manifest.json --contract-source docs/runs/2026-11-25-reshape-it-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6 --contract-digest sha256:37d6f05a80f4775abbf74535c5ce628c88de4890f0037ed75880dc4ebfaee799 --unit-class mutation --lighting dark-eligible --lane A --execute-nc --nc-command 'python3 -m unittest tests.test_reshape_net_verify_diff'`

Output (verbatim, exit 0, retained in `verifier.txt`):

```
NOTE: redaction: gitleaks at /home/aq-users/mDn3vRscxATUnCmKRdQLXELIVrl1/.local/bin/gitleaks is worker-writable — it can only add hits above the built-in floor, so it is consulted and recorded (h409 R2)
NOTE: --base not given — ancestry check skipped (pre-merge/offline)
NOTE: --base not given — base_sha, the content the executed control restores, is bound to no branch (worker-chosen on this lane)
NOTE: commands ledger FRESH — 1 exit-0 record(s) bound to head_sha's tree 8990f9d2d5b7. This is the worker's own runner, so the coordinator's clean-env re-run at head_sha still stands as the stronger authority (evidence-manifest.md §2)
NOTE: negative control EXECUTED — with the hand control applied at head_sha the bound command exited 1 on an assertion failure (RED, as required)
NOTE: the same command exits 0 at clean head_sha, before AND after the control run — the RED above is the control's doing, not a broken suite or a first-run side effect
NOTE: independent review waived — dark-eligible unit (gate-classification.md); the EXECUTED negative control + tests are the oracle, not a human review
verify: OK — all required checks passed
```

## WIP-curve protocol row

| Wave | WIP setting | Builder throughput | Verification latency | Rework rate | Freshness violations | Note |
|---|---|---|---|---|---|---|
| `wave=1` | `builders=1 reviewers=1` | `throughput=3/h` | `latency_median=45s latency_max=45s` | `rework=0/1` | `freshness=0` | RV-D3 single-seam deepening, Round 1 blind GO |

## Deviations and lessons (recorded, not hidden)

- D1: Executed on standalone AQ Linux harness without the Orca desktop app (`same-vendor-fresh` independent `research` subagent review rather than cross-vendor Orca terminal). Recorded transparently rather than overstated.
- L1: Binding host globals via `_verify_diff.bind(globals())` instead of `sys.modules[__name__]` keeps custom `importlib.util.spec_from_file_location` loads and `mock.patch.object(verify, "_git", ...)` seams intact across every test harness.

## Run-close integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `docs/runs/2026-11-25-reshape-it-selfrun/contract.json` | `37d6f05a80f4775abbf74535c5ce628c88de4890f0037ed75880dc4ebfaee799` | coordinator frozen contract 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/manifest.json` | `0957cd3e77dc2f955af7e0973763bb1ef91af40256f8caf1fa9c86c729cab5b5` | evidence-run.py + manifest assembly 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/negctrl.txt` | `ee18ad994aa3a48828a8338ed37e69789b0a64fcae8c97dc183d59fc908bf87b` | throwaway worktree hand mutant replay 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/revert-width-check.txt` | `968e4febff7a5935934679ad578778472b79c2efc3aa7330bd61fc196e0a692c` | revert width probe (84 -> 91) 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/review.txt` | `8b876d7ec9124d5c4946829c5d3939bc7ddcd353b8bd9d1d849190301e595725` | independent build-blind reviewer (Round 1 GO) 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/tests.txt` | `87e0fc072e190b6834bcdb944df770cdde91fa9dcf2ead9314a50335f200ed3f` | evidence-run.py at 4ad16df4 2026-11-25 |
| `docs/runs/2026-11-25-reshape-it-selfrun/verifier.txt` | `3046c2857d1ffb01ad6edcb419d4974a5e150e4a477307e64dcfbf38ad790f06` | evidence-run.py verify.py GREEN 2026-11-25 |
