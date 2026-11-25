# document-it — DOC-1 self-run summary envelope (2026-11-25)

**Bindable core:** [`docs/runs/2026-11-25-document-it-self-run.md`](../../runs/2026-11-25-document-it-self-run.md) (`inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439`, `verifier=GREEN`).  
**Terminal outcome:** `DOCUMENTED` — live machine extraction of 16 CLI commands, 19 MCP tools, 10 MCP resources, 5 Action outputs, and 18 doc-embedded AST-verified `file:symbol` anchors in `docs/cli-and-mcp.md`, resolved one-hop Markdown link reachability from `README.md` and `docs/README.md`, and CI/local wiring (`scripts/check.py`, `.github/workflows/validate.yml`, `.github/workflows/product-package.yml`).

## Negative control

1. **Rename-to-RED fresh subprocess control:** renaming doc-anchored `open_fleet/solo_review.py:run_solo_review` across all callers (`cli.py`, `mcp_server.py`, `ui_server.py`) turns `python3 -I scripts/extract_product_surface.py --check` RED (exit 1, zero `ImportError`).
2. **Hand mutant killed at `head_sha` (`cfa3bd63`):** forcing `ok = True` in `scripts/extract_product_surface.py` AST anchor verification turns `tests.test_product_surface_and_wheel.TestProductSurfaceDocumentationAndRenameControl` RED (`FAILED (failures=2)`, `AssertionError`, exit 1); clean `head_sha` exits 0 before and after (`negctrl.txt`, executed by `verify.py --execute-nc`).

## Integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `negctrl.txt` | `874995ac97df8159b4b514887dfcc5d4210398cd5c88a0fc831fb53ef062e238` | throwaway worktree hand mutant replay (2026-11-25) |

## Runner credit

Runner: Ravindra Kumar (@ravidsrk) · 3-round independent build-blind review (`R1 NO-GO -> R2 NO-GO -> R3 GO`).
