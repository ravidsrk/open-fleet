# The Rust Engine (`crates/*`)

`open-fleet` pairs a canonical plain-Markdown mission catalog (`skills/`, `playbooks/`,
`runtime/*.md`) with a single static Rust binary (`open-fleet`) built from the Cargo workspace
at the repository root.

Every hot-path guardrail, diff scanner, cryptographic verifier, and multi-harness installer
moves into this binary wave by wave while staying pinned byte-for-byte to the repository's
existing adversarial test suites (`CLI-CONTRACT.md`).

## Workspace Layout

```text
Cargo.toml                    Cargo workspace root (fat LTO, stripped release binary)
ENGINE_VERSION                Pinned engine release version (read by launchers and CI)
CLI-CONTRACT.md               Byte-for-byte CLI behavior and exit-code contract
scripts/open-fleet            Thin POSIX launcher (local target -> cache -> verified release)
cli/                          npm wrapper (`npx open-fleet`) + per-platform optional packages
crates/
  of-common/                  Shared git custody (`gitexec`), hunk-counted `diffparse`,
                              DECISIONS ledger parser + native Ed25519 grant verification
  of-floor/                   Native `floor_guard` engine (all 6 rules + structural TOML/INI
                              guard surface + base-ref signed waiver resolution)
  of-install/                 Multi-harness detector, skill installer, atomic Claude hook
                              merger, and fast `doctor` diagnostics
  of-ledgers/                 Native cryptographic ledgers: hash-chained `egress` receipts
                              and `decisions` validation + Ed25519 human grant signing
  of-catalog/                 Native YAML-frontmatter catalog discovery, certification
                              rollup, and TF-IDF mission intent router
  of-verify/                  Native verification & control suite: `diff-scope`, `quarantine`,
                              `dispatch-sign`, `inventory`, `proof-status`, `preflight`,
                              `chain-check`, progressive `session` state machines, `solo-review`,
                              `ci-check`, and `readiness`
  of-mcp/                     Zero-Python JSON-RPC 2.0 stdio MCP server (20 native tools)
  of-cli/                     The `open-fleet` binary: native verbs + strangler-fig delegation
```

## Build, Test, and Oracle Gates

```bash
cargo build --release -p of-cli        # target/release/open-fleet
cargo test --workspace                 # Rust unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
python3 -I scripts/rust_floor_oracle.py          # 103 end-to-end floor_guard CLI tests
python3 -I scripts/rust_egress_oracle.py         # 58 end-to-end egress CLI tests
python3 -I scripts/rust_decisions_oracle.py      # 94 end-to-end decisions CLI tests
python3 -I scripts/rust_diff_scope_oracle.py     # 63 end-to-end diff_scope CLI tests
python3 -I scripts/rust_quarantine_oracle.py     # 21 end-to-end quarantine CLI tests
python3 -I scripts/rust_dispatch_sign_oracle.py  # 23 end-to-end dispatch-sign CLI tests
python3 -I scripts/rust_inventory_oracle.py      # 54 end-to-end inventory CLI tests
python3 -I scripts/rust_proof_status_oracle.py   # 8 end-to-end proof-status CLI tests
python3 -I scripts/rust_preflight_oracle.py      # 36 end-to-end preflight + capabilities CLI tests
python3 -I scripts/rust_chain_check_oracle.py    # 11 end-to-end chain_check CLI tests
python3 -I scripts/rust_product_oracle.py        # catalog, router, sessions, solo/ci/readiness & 20-tool MCP parity
```

## Strangler-Fig Migration Roadmap

| Wave | Native Crates | Replaces | Oracle Gate |
|---|---|---|---|
| **Wave 1 (landed)** | `of-common`, `of-floor`, `of-install`, `of-cli` | `floor_guard.py`, `open_fleet/setup.py`, thin launchers + release pipeline | `scripts/rust_floor_oracle.py` (103 tests) |
| **Wave 2A + 3 (landed)** | `of-ledgers`, `of-catalog`, `of-mcp` | `egress.py`, `decisions.py`, `open_fleet/catalog.py`, `open_fleet/mcp_server.py` | `scripts/rust_egress_oracle.py` (58), `scripts/rust_decisions_oracle.py` (94), `scripts/rust_product_oracle.py` |
| **Wave 2B-1 (landed)** | `of-verify` (Part 1) | `diff_scope.py`, `quarantine_check.py`, `dispatch-sign.py`, `inventory.py`, `proof_status.py` | `rust_diff_scope_oracle.py` (63), `rust_quarantine_oracle.py` (21), `rust_dispatch_sign_oracle.py` (23), `rust_inventory_oracle.py` (54), `rust_proof_status_oracle.py` (8) |
| **Wave 3B (landed)** | `of-verify`, `of-mcp`, `of-cli` | `preflight.py`, `chain_check.py`, `open_fleet/sessions.py`, `solo_review.py`, `ci_action.py`, `readiness.py` | `rust_preflight_oracle.py` (36), `rust_chain_check_oracle.py` (11), `rust_product_oracle.py` (8) |
| **Wave 2B-2 (next)** | `of-verify`, `of-ledgers` | `events.py`, `run_report.py`, `verify.py` | `bench/vf-bench`, `tests/test_verify.py`, `tests/test_events.py`, `tests/test_run_report.py` |
| **Wave 1.5** | `of-hook` | `runtime/scripts/deny-hook.sh` (6.8k LOC -> native pre-tool hook) | `tests/test_deny_hook.py`, `tests/test_deny_hook_conformance.py`, `tests/test_deny_hook_multi_harness.py`, `tests/test_trajectory_evals.py` |
| **Deferred / Kept** | — | `merge_queue.py`, `posix.py`, `eval.py`, `ablation.py` remain in Python; `skills/`, `playbooks/`, `runtime/*.md` stay canonical Markdown | Existing Python suites |

## Distribution Channels

- **GitHub Releases (`engine-v*`):** Pre-built stripped static binaries + `.sha256` checksums for `darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`, and `windows-x64` (`.github/workflows/release-engine.yml`).
- **npm (`cli/`):** `npx open-fleet` resolves the matching `@open-fleet/cli-<os>-<arch>` optional package or falls back to a SHA-256-verified download cached in `~/.open-fleet/bin/<version>/`.
- **Thin shell launcher (`scripts/open-fleet`):** Zero-dependency POSIX launcher usable directly inside skill scripts and CI without Python or Rust installed.
