# reshape-it — RV-D3 self-run summary envelope (2026-11-25)

**Bindable core:** [`docs/runs/2026-11-25-reshape-it-self-run.md`](../../runs/2026-11-25-reshape-it-self-run.md) (`inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439`, `verifier=GREEN`).  
**Terminal outcome:** `RESHAPED` — extracted `runtime/scripts/verify.py`'s unified-diff and hunk-binding helpers into hashed sibling `runtime/scripts/_verify_diff.py` (`WIDTH` 91 → 84, `DEPTH` 5228 → 5036) behind pre-pinned RV-C3 characterization net `tests/test_reshape_net_verify_diff.py`.

## Negative control

1. **Hand mutant killed at `head_sha` (`4ad16df4`):** disabling `_bind_hunks_to_change` overlap check (`runtime/scripts/_verify_diff.py:163`) turns `python3 -m unittest tests.test_reshape_net_verify_diff` RED (`AssertionError`, exit 1); clean `head_sha` exits 0 before and after (`negctrl.txt`, executed by `verify.py --execute-nc`).
2. **Revert enlarges interface width:** restoring `runtime/scripts/verify.py` from `base_sha` (`6b8c2af3`) enlarges `WIDTH` from `84` back to `91` (`+7` symbols).

## Integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `negctrl.txt` | `ee18ad994aa3a48828a8338ed37e69789b0a64fcae8c97dc183d59fc908bf87b` | throwaway worktree hand mutant replay (2026-11-25) |

## Runner credit

Runner: Ravindra Kumar (@ravidsrk) · independent build-blind review GO (Round 1 of 3).
