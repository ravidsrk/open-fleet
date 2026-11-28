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
  of-install/                 Compile-time embedded canonical catalog (`build.rs` + atomic
                              `~/.open-fleet/catalog/<ver>-<sha12>/` materialization), multi-harness
                              detector, skill installer, dual `floor` + `deny` Claude hook merger,
                              and fast `doctor` diagnostics
  of-ledgers/                 Native cryptographic & telemetry ledgers: hash-chained `egress`
                              receipts, `decisions` Ed25519 grant signing, and append-only
                              `events` ledger + WIP-curve derivation (with bundled SQLite)
  of-catalog/                 Native YAML-frontmatter catalog discovery, certification
                              rollup, and TF-IDF mission intent router
  of-verify/                  Native verification & control suite: `verify` (SHA-bound manifest
                              verifier + executed negative control), `run-report`, `diff-scope`,
                              `quarantine`, `dispatch-sign`, `inventory`, `proof-status`,
                              `preflight`, `chain-check`, progressive `session` state machines,
                              `solo-review`, `ci-check`, and `readiness`
  of-hook/                    Native PreToolUse deny-hook engine (`open-fleet hook --mode deny` /
                              `open-fleet deny-hook`): quote-aware shell lexer, brace/heredoc/pipe
                              analyzer, self-guard, RO write floor, egress receipt gate, SQLite WAL
                              file-touch recorder, and 11-harness `--settings` / `--verify-settings`
  of-mcp/                     Zero-Python JSON-RPC 2.0 stdio MCP server (23 native tools)
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
python3 -I scripts/rust_events_oracle.py         # 98 end-to-end events ledger + WIP-curve CLI tests
python3 -I scripts/rust_run_report_oracle.py     # 85 end-to-end run_report proof-binding CLI tests
python3 -I scripts/rust_verify_oracle.py         # VF-Bench (0% false-done, 0% false-reject) + test_verify CLI tests
python3 -I scripts/rust_deny_hook_oracle.py      # 398 end-to-end deny-hook, multi-harness, bash-conformance & trajectory tests
python3 -I scripts/rust_product_oracle.py        # catalog, router, sessions, solo/ci/readiness & 23-tool MCP parity
```

## Strangler-Fig Migration Roadmap

| Wave | Native Crates | Replaces | Oracle Gate |
|---|---|---|---|
| **Wave 1 (landed)** | `of-common`, `of-floor`, `of-install`, `of-cli` | `floor_guard.py`, `open_fleet/setup.py`, thin launchers + release pipeline | `scripts/rust_floor_oracle.py` (103 tests) |
| **Wave 2A + 3 (landed)** | `of-ledgers`, `of-catalog`, `of-mcp` | `egress.py`, `decisions.py`, `open_fleet/catalog.py`, `open_fleet/mcp_server.py` | `scripts/rust_egress_oracle.py` (58), `scripts/rust_decisions_oracle.py` (94), `scripts/rust_product_oracle.py` |
| **Wave 2B-1 (landed)** | `of-verify` (Part 1) | `diff_scope.py`, `quarantine_check.py`, `dispatch-sign.py`, `inventory.py`, `proof_status.py` | `rust_diff_scope_oracle.py` (63), `rust_quarantine_oracle.py` (21), `rust_dispatch_sign_oracle.py` (23), `rust_inventory_oracle.py` (54), `rust_proof_status_oracle.py` (8) |
| **Wave 3B (landed)** | `of-verify`, `of-mcp`, `of-cli` | `preflight.py`, `chain_check.py`, `open_fleet/sessions.py`, `solo_review.py`, `ci_action.py`, `readiness.py` | `rust_preflight_oracle.py` (36), `rust_chain_check_oracle.py` (11), `rust_product_oracle.py` (8) |
| **Wave 2B-2 (landed)** | `of-verify`, `of-ledgers`, `of-mcp` | `events.py`, `run_report.py`, `verify.py` (`_verify_sig.py`, `_verify_diff.py`) | `rust_events_oracle.py` (98), `rust_run_report_oracle.py` (85), `rust_verify_oracle.py` (VF-Bench + CLI) |
| **Wave 1.5 (landed)** | `of-hook` | `runtime/scripts/deny-hook.sh` (6.8k LOC -> native pre-tool hook) | `scripts/rust_deny_hook_oracle.py` (398 tests across `test_deny_hook`, `test_deny_hook_multi_harness`, `test_deny_hook_conformance`, `test_trajectory_evals`) |
| **Phase A (landed)** | `of-install`, `of-cli`, `of-verify` | Compile-time embedded canonical catalog (`~/.open-fleet/catalog/<ver>-<sha12>/`), zero-clone standalone binary, dual `floor` + `deny` Claude hooks in `init`, `scripts/install-engine.sh`, `open-fleet.rb` Homebrew formula, gated npm release job | `scripts/rust_product_oracle.py` (standalone isolated temp-dir suite) + `tests/test_rust_engine_packaging.py` |
| **Phase B (landed)** | `of-cli` (`ui`), `of-verify` (`demo`), `of-hook`, `of-mcp` | Native zero-Python `open-fleet ui` (stdlib HTTP/SSE Mission Control), native zero-Python `open-fleet demo` & MCP `fleet_run_demo`, standalone `deny-hook --settings` -> `--verify-settings`, Rust-first cutover in `verify-gate.sh`, `.github/actions/open-fleet-verify`, `open_fleet/cli.py`, and `README.md` | `scripts/rust_product_oracle.py` (10 tests incl. live HTTP/SSE UI, standalone demo & deny-hook round-trip) + `test_verify_gate.py` |
| **Phase C (`v1.0.0`, landed)** | `of-verify`, `of-cli`, `of-install` | Binary-bound transcript provenance (`toolchain.engine_binary_sha256` + W3-11 mid-run binary drift check + standalone `dispatch-sign sign-transcript`), native read-only SQLite `open-fleet status` & `ui` workspace state, native `open-fleet mcp --print-config`, `engine: "rust"` attestation in `doctor` | `scripts/rust_product_oracle.py` (11 tests incl. standalone binary-bound transcript signing/tamper refusal, live SQLite status & MCP config) + all 15 parity oracles |
| **Frozen Reference / Kept** | — | `skills/`, `playbooks/`, `runtime/*.md` stay canonical Markdown; Python reference copies under `runtime/scripts/` & `runtime/providers/` remain intact to satisfy the human-frozen `CONSTRAINTS.md` D1/D8/D9 (`.coveragerc` >= 80%) guard surface until an explicit signed one-way human decision in `docs/DECISIONS.md` migrates D9 coverage to Rust (`cargo-llvm-cov`) | Existing Python suites + `floor_guard.py` |

## Single-Source-of-Truth Status (`v1.0.0`)

Every user-facing verb (`doctor`, `init`, `missions`, `route`, `show`, `status`, `certification`/`certify`, `overview`, `demo`, `ui`, `mcp`, `session`, `solo-review`, `ci-check`, `readiness`, `preflight`, `verify`, `floor`, `egress`, `decisions`, `diff-scope`, `quarantine`, `dispatch-sign`, `inventory`, `proof-status`, `chain-check`, `events`, `run-report`, `hook`, `deny-hook`) and all 24 MCP tools execute **100% natively in the single static `open-fleet` v1.0.0 Rust binary** with zero Python runtime and zero repository clone required.

### Optional Post-v1.0 Legacy Python Retirement Runbook (Human One-Way Gate)

The frozen `CONSTRAINTS.md` D1/D8/D9 contract pins `unittest` and `.coveragerc` (`fail_under = 80` over `scripts/*`, `runtime/scripts/*`, `runtime/providers/*`) under `floor_guard.py`. Removing the legacy Python reference implementations under `runtime/scripts/` requires an explicit signed one-way human decision in `docs/DECISIONS.md` (recorded on `origin/main` via `open-fleet decisions sign-grant`) authorizing:
1. Updating `CONSTRAINTS.md` D9 to measure Rust coverage (`cargo-llvm-cov`) instead of Python `.coveragerc`.
2. Retiring the Python reference copies once all historical `validate/vfbench_replay` and `validate/tests` shards bind directly to the `open-fleet` binary.

## Distribution Channels

- **Curl-pipe zero-Python installer (`scripts/install-engine.sh`):** `curl -fsSL https://raw.githubusercontent.com/ravidsrk/open-fleet/main/scripts/install-engine.sh | sh` downloads the platform binary + `.sha256` checksum, verifies SHA-256 fail-closed, and installs `~/.local/bin/open-fleet` (no git clone, no Python, no Rust required).
- **GitHub Releases (`engine-v*`) & Homebrew formula (`open-fleet.rb`):** Pre-built stripped static binaries + `.sha256` checksums for `darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`, and `windows-x64`, plus a generated `open-fleet.rb` Homebrew formula attached to every release (`.github/workflows/release-engine.yml`).
- **npm (`cli/`):** `npx @open-fleet/cli` resolves the matching `@open-fleet/cli-<os>-<arch>` optional package or falls back to a SHA-256-verified download cached in `~/.open-fleet/bin/<version>/` (auto-published when `NPM_TOKEN` is configured).
- **Thin shell launcher (`scripts/open-fleet`):** Zero-dependency POSIX launcher usable directly inside skill scripts and CI without Python or Rust installed.
