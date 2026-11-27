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
  of-cli/                     The `open-fleet` binary: native verbs + strangler-fig delegation
```

## Build, Test, and Oracle Gate

```bash
cargo build --release -p of-cli        # target/release/open-fleet
cargo test --workspace                 # Rust unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
python3 -I scripts/rust_floor_oracle.py  # runs test_floor_guard.py end-to-end against the Rust binary
```

## Strangler-Fig Migration Roadmap

| Wave | Native Crates | Replaces | Oracle Gate |
|---|---|---|---|
| **Wave 1 (landed)** | `of-common`, `of-floor`, `of-install`, `of-cli` | `floor_guard.py`, `open_fleet/setup.py`, thin launchers + release pipeline | End-to-end CLI suite from `tests/test_floor_guard.py` (103 hermetic-repo tests) via `scripts/rust_floor_oracle.py` |
| **Wave 1.5 (next)** | `of-hook` | `runtime/scripts/deny-hook.sh` (6.8k LOC -> ~2ms native pre-tool hook) | `tests/test_deny_hook.py`, `tests/test_trajectory_evals.py`, `tests/test_adversarial_security.py` |
| **Wave 2** | `of-ledgers`, `of-verify` | `egress.py`, `decisions.py`, `events.py`, `verify.py`, `negative_control.py` | `bench/vf-bench`, `tests/test_verify.py`, `tests/test_events.py`, `tests/test_decisions.py`, `tests/test_egress.py` |
| **Wave 3** | `of-mcp`, `of-ui`, `of-catalog` | `open_fleet/{mcp_server,ui_server,catalog,cli}.py` | `tests/test_product_cli.py`, `tests/test_product_mcp.py`, `tests/test_product_ui.py` |
| **Deferred / Kept** | — | `merge_queue.py`, `posix.py`, `eval.py`, `ablation.py` remain in Python; `skills/`, `playbooks/`, `runtime/*.md` stay canonical Markdown | Existing Python suites |

## Distribution Channels

- **GitHub Releases (`engine-v*`):** Pre-built stripped static binaries + `.sha256` checksums for `darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`, and `windows-x64` (`.github/workflows/release-engine.yml`).
- **npm (`cli/`):** `npx open-fleet` resolves the matching `@open-fleet/cli-<os>-<arch>` optional package or falls back to a SHA-256-verified download cached in `~/.open-fleet/bin/<version>/`.
- **Thin shell launcher (`scripts/open-fleet`):** Zero-dependency POSIX launcher usable directly inside skill scripts and CI without Python or Rust installed.
