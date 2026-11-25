# Run report — document-it self-run, 2026-11-25

RUN: mission=document-it tier=self-run inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439 manifest=docs/runs/2026-11-25-document-it-selfrun/manifest.json verifier=GREEN waves=1

Self-run of `document-it` against this catalog's `open_fleet` product surface (`DOC-1`): live machine extraction of 16 CLI commands, 19 MCP tools, 10 MCP resources, 5 reusable GitHub Action outputs, and 18 doc-embedded AST-verified `file:symbol` anchors in `docs/cli-and-mcp.md`, resolved one-hop Markdown reachability from `README.md` and `docs/README.md`, three-round build-blind review (`R1 NO-GO` → `R2 NO-GO` → `R3 GO`), and `verify.py --execute-nc` **GREEN**.

| Field | Value |
|---|---|
| Mission | `document-it` — SKILL unchanged by this unit |
| Tier claimed | `self-run` (against this catalog) |
| Target | `open_fleet` public surface (`open_fleet/cli.py`, `open_fleet/mcp_server.py`, `.github/actions/open-fleet-verify/action.yml`) → `docs/cli-and-mcp.md` + `scripts/extract_product_surface.py` |
| Fixed point | `base_sha=4ad16df406c6df3bb2d13f0037ec274802666b61` · `head_sha=cfa3bd63f78df5f0e5e7ee66817ba466d860340b` · contract `docs/runs/2026-11-25-document-it-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6` (`sha256:f61cce16eb641ba77d6e22f5109030f7c27b6bbc4ce857fee9d008ea9c0efa42`) |
| Reviewer | Three independent fresh-context build-blind `research` subagents (`same-vendor-fresh`): Round 1 **NO-GO** (`review-r1.txt`) → Round 2 **NO-GO** (`review-r2.txt`) → Round 3 **GO** (`review.txt`) |
| Substrate note | Executed in AQ Linux worktree without Orca desktop app installed; all verification executed via repo-native `evidence-run.py` + `verify.py --execute-nc` |

## Terminal state

**DOCUMENTED** — map re-derived at `cfa3bd63` (`surface-map.json`) shows 0 critical gaps across 16 CLI commands (scoped to `## Unified CLI Commands`), 19 MCP tools, 10 MCP resources, 5 Action outputs, and 18 AST-verified doc-embedded `file:symbol` anchors; resolved one-hop Markdown link reachability holds from both `README.md` and `docs/README.md`; rename-to-RED negative control verified in a fresh `-I` subprocess; wired into `scripts/check.py`, `.github/workflows/validate.yml`, `.github/workflows/product-package.yml`, and `tests/test_entrypoint_guard.py`.

## Convergence proof

1. **Machine-derived coverage map at final head (`surface-map.json`):** `python3 -I scripts/extract_product_surface.py --check --json` derives every entity directly from live code and `docs/cli-and-mcp.md` with zero hand-copied lists (`ok: true`, 0 errors).
2. **Rename-to-RED negative control (`negctrl.txt` + `verify.py --execute-nc`):**
   - `tests/test_product_surface_and_wheel.py::test_rename_negative_control_turns_claim_check_red` renames doc-anchored `open_fleet/solo_review.py:run_solo_review` across all callers (`cli.py`, `mcp_server.py`, `ui_server.py`) and proves a fresh `python3 -I` subprocess exits 1 on the exact AST anchor error with zero `ImportError`.
   - Hand mutant forcing `ok = True` in `scripts/extract_product_surface.py` was executed live by `verify.py --execute-nc` → exit 1 (`FAILED (failures=2)`, `AssertionError`), clean `head_sha` exits 0 before AND after.
3. **Real multi-round build-blind review:**
   - Round 1 (`review-r1.txt`, **NO-GO**): caught hand-copied `CORE_SYMBOL_ANCHORS` decoupled from `docs/cli-and-mcp.md`, missing `KeyError` / fail-open guards, and missing `check.py` / `validate.yml` wiring.
   - Round 2 (`review-r2.txt`, **NO-GO**): caught stale `sys.modules` cache masking `ui_server.py` `ImportError` in the rename control and overly permissive relative Markdown link matching.
   - Round 3 (`review.txt`, **GO**): verified all fixes across all three axes (0 Critical, 0 Required).

## Verifier outcome (recorded exactly)

Invocation recorded through `evidence-run.py` on clean committed tree `ff05bebc`:

`python3 runtime/scripts/evidence-run.py --label verifier --manifest docs/runs/2026-11-25-document-it-selfrun/manifest.json --artifact docs/runs/2026-11-25-document-it-selfrun/verifier.txt -- python3 runtime/scripts/verify.py --manifest docs/runs/2026-11-25-document-it-selfrun/manifest.json --contract-source docs/runs/2026-11-25-document-it-selfrun/contract.json@ce5dc5ae838ada69a9b77daccf18e04537845df6 --contract-digest sha256:f61cce16eb641ba77d6e22f5109030f7c27b6bbc4ce857fee9d008ea9c0efa42 --unit-class mutation --lighting dark-eligible --lane A --execute-nc --nc-command 'python3 -m unittest tests.test_product_surface_and_wheel.TestProductSurfaceDocumentationAndRenameControl'`

Output (verbatim, exit 0, retained in `verifier.txt`):

```
NOTE: redaction: gitleaks at /home/aq-users/mDn3vRscxATUnCmKRdQLXELIVrl1/.local/bin/gitleaks is worker-writable — it can only add hits above the built-in floor, so it is consulted and recorded (h409 R2)
NOTE: --base not given — ancestry check skipped (pre-merge/offline)
NOTE: --base not given — base_sha, the content the executed control restores, is bound to no branch (worker-chosen on this lane)
NOTE: commands ledger FRESH — 1 exit-0 record(s) bound to head_sha's tree b03a4fbb85fb. This is the worker's own runner, so the coordinator's clean-env re-run at head_sha still stands as the stronger authority (evidence-manifest.md §2)
NOTE: negative control EXECUTED — with the hand control applied at head_sha the bound command exited 1 on an assertion failure (RED, as required)
NOTE: the same command exits 0 at clean head_sha, before AND after the control run — the RED above is the control's doing, not a broken suite or a first-run side effect
NOTE: independent review waived — dark-eligible unit (gate-classification.md); the EXECUTED negative control + tests are the oracle, not a human review
verify: OK — all required checks passed
```

## WIP-curve protocol row

| Wave | WIP setting | Builder throughput | Verification latency | Rework rate | Freshness violations | Note |
|---|---|---|---|---|---|---|
| `wave=1` | `builders=1 reviewers=1` | `throughput=1.5/h` | `latency_median=120s latency_max=180s` | `rework=2/1` | `freshness=0` | 2 blind-review rework cycles (R1 NO-GO -> R2 NO-GO -> R3 GO) |

## Deviations and lessons (recorded, not hidden)

- D1: Executed on standalone AQ Linux harness without the Orca desktop app (`same-vendor-fresh` independent `research` subagents).
- L1: Genuine build-blind review earned its keep twice on this single unit: Round 1 eliminated hand-copied anchors (converting them into real doc-parsed AST anchors, which immediately caught two symbol typos `route_goal` and `collect_status`), and Round 2 eliminated a subtle `sys.modules` cache bug masking an `ImportError` in `ui_server.py`.

## Run-close integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `docs/runs/2026-11-25-document-it-selfrun/contract.json` | `f61cce16eb641ba77d6e22f5109030f7c27b6bbc4ce857fee9d008ea9c0efa42` | coordinator frozen contract 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/manifest.json` | `6dded8402ad33fd47a7aac17f9057245e3c7f7829a7e41c85ab99f3bff08f111` | evidence-run.py + manifest assembly 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/negctrl.txt` | `874995ac97df8159b4b514887dfcc5d4210398cd5c88a0fc831fb53ef062e238` | throwaway worktree hand mutant replay 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/review-r1.txt` | `c5bece4b522d284beb9af358e088482aa9a617850bd4a121519ad64cf0fecedb` | independent build-blind reviewer (Round 1 NO-GO) 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/review-r2.txt` | `beb1c251ac9f0f90ecf868d61625154813d57c7fdc13065e123441d8860f0dac` | independent build-blind reviewer (Round 2 NO-GO) 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/review.txt` | `2f39d83eaf0d0190950e5d9e2a98bb89bc9beb93609ebc2a04e7be55c015e8d9` | independent build-blind reviewer (Round 3 GO) 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/surface-map.json` | `48fba7f8d00ce86d98037566dbb2d6a613f3b4e7f8514bf5a88af43de83d36c3` | extract_product_surface.py --check --json 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/tests.txt` | `206c78c65108050ffc57c2cd969b79aebb0288d2a299be0a190f4ed35c73ebcf` | evidence-run.py at cfa3bd63 2026-11-25 |
| `docs/runs/2026-11-25-document-it-selfrun/verifier.txt` | `7fa3b9766e2af35be2fd08addb67612091c8ec196939cac4ce59b0f736f1bb80` | evidence-run.py verify.py GREEN 2026-11-25 |
