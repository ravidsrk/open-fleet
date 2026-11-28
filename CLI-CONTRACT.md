# CLI Contract — `open-fleet` Engine

Every native Rust verb in the `open-fleet` binary is specified here and pinned byte-for-byte
against the repository's adversarial oracle suites (`tests/test_floor_guard.py`,
`tests/test_rust_floor_oracle.py`, and subsequent wave oracles).

The canonical Markdown catalog (`skills/`, `playbooks/`, `runtime/*.md`) stays plain Markdown.
The native binary replaces interpreter-bound hot paths one wave at a time via strangler-fig
delegation, never drifting from exit codes, stderr diagnostics, or fail-closed guarantees.

## Global Contract

- Binary name: `open-fleet` (Cargo package `of-cli`).
- Version: `open-fleet --version` prints `open-fleet <ENGINE_VERSION>`.
- Never exits `0` on an unreadable repository, malformed diff, invalid key, or missing ref:
  every could-not-run condition exits `2` (`EXIT_CANNOT_RUN`).
- No secret value or matched credential text is ever printed to stdout or stderr; only rule IDs,
  file/line locations, and pattern names appear.

## Wave 1 Native Verbs

### `open-fleet floor` (replaces `runtime/scripts/floor_guard.py`)

```text
open-fleet floor [--base REF] [--constraints PATH] [--waivers PATH] [--repo DIR] [--quiet] [--json]
```

| Flag | Default | Meaning |
|---|---|---|
| `--base REF` | `origin/HEAD` → `origin/main` → `origin/master` → `main` → `master` | Resolved once by exact ref name (`of_common::gitexec::base_commit`); never expanded across ref namespaces. |
| `--constraints PATH` | `CONSTRAINTS.md` | Constraints table whose numbered floors cannot move down or add unwaived exceptions. |
| `--waivers PATH` | `docs/DECISIONS.md` | Repo-relative DECISIONS log read **at the resolved base commit** (never from the checked-out tree). |
| `--repo DIR` | `.` | Repository to guard. |
| `--quiet` | `false` | Suppress clean banner (`floor-guard: clean`). |
| `--json` | `false` | Emit structured JSON report (`status`, `base`, `findings`, `waived`, `exit_code`). |

**Rules enforced (all six):**
1. `silenced-checker` — linter/checker/coverage/scanner suppression comments/attributes on added lines.
2. `test-made-easier` — skipped/ignored tests + `renamed-out-of-discovery` (`test_x` → `_test_x` / `TestX` → `testX`).
3. `unfinished-work` — stub markers, empty catches, swallowed exception handlers, stub returns.
4. `assertion-removed` — deleted assertions in surviving or moved (`>= 50%` substantive line similarity) test files.
5. `threshold-lowered` — lowered, deleted, re-keyed, comparator-flipped, or duplicated numbered rows in constraints files (with Unicode NFKC folding).
6. `new-exception` & `guard-surface` — new exception rows/bullets and touches to frozen guard files/keys/TOML/INI sections.

**Git custody & waivers:**
- Working-tree diffs run inside an isolated temporary git custody dir (`of_common::gitexec::Custody`) with no repo-controlled hooks/filters/drivers, FIFO/symlink refusal (`O_NOFOLLOW | O_NONBLOCK`), and `--no-renames --text --no-color --unified=0`.
- Waivers require `id = floor-waiver:<rule>:<exact-path-or-dir/**>`, `class = one-way`, `answer = allow`, `[source=human:<name>]`, and valid Ed25519 signature over payload v3/v2 when `.orca/human-grant-pubkey` is pinned at the base ref.

**Exit codes:**
- `0` — clean (or all findings waived by standing one-way human grants on the base ref).
- `1` — one or more unwaived floor violations.
- `2` — could not run (not a git repo, unresolvable/ambiguous base, local base under `OPEN_FLEET_PROVENANCE`/`ORCA_PROVENANCE`, malformed diff, unreadable/blocked git config, malformed base pubkey, outside-repo `--waivers`).

### `open-fleet doctor` (native diagnostics)

```text
open-fleet doctor [--repo DIR] [--json]
```

Checks native engine version, git availability, detected coding-agent harnesses (`claude`,
`cursor`, `codex`, `gemini`, `opencode`, `copilot`, `antigravity`, `windsurf`, `hermes`, `omp`,
`pi`, `grok`), configured Claude hooks, catalog root, and runtime mode (`auto` / `posix` / `orca`).
Exits `0` when ready, `1` when warnings/missing prerequisites exist.

### `open-fleet install` / `open-fleet init` (multi-harness setup & hooks)

```text
open-fleet init [--harness claude|cursor|codex|gemini|opencode|antigravity|all]
                [--scope user|project] [--mode symlink|copy] [--home DIR] [--repo DIR]
                [--with-hooks] [--dry-run] [--json]
```

- Installs canonical `skills/` into each selected harness's native skills directory (works standalone zero-clone via the compile-time embedded catalog materialized atomically to `~/.open-fleet/catalog/<version>-<sha12>/`; an enclosing checkout or `OPEN_FLEET_ROOT` always takes precedence).
- With `--with-hooks` (default on `init`), atomically merges BOTH the native `open-fleet floor --quiet` (`Stop`/`TaskCompleted`) AND `open-fleet hook --mode deny` (`PreToolUse`) guards into Claude Code `settings.json` without clobbering existing user hooks.
- Exits `0` on success, `2` on usage or unreadable source/target errors.

### `open-fleet egress` (native hash-chained receipts)

```text
open-fleet egress [--ledger PATH] write --sink S --host H --payload-class C --consent G [--bytes N] [--payload-file F] [--payload-sha256 HEX] [--ts ISO]
open-fleet egress [--ledger PATH] verify [--expect-head SHA] [--expect-ancestor SHA]... [--allow-empty]
open-fleet egress [--ledger PATH] head
open-fleet egress [--ledger PATH] grants [--json] [--expect-head SHA] [--expect-ancestor SHA]...
```

- Exact parity with `runtime/scripts/egress.py` (canonical JSON v2 + v1 prefix migration, SHA-256 `id` + `prev` chaining, linked-worktree back-link proof, `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, `flock`, `fsync`, mode `0600`).
- Exit codes: `0` ok, `2` usage, `3` fail-closed/tamper, `4` no receipts (`verify` without `--allow-empty`).

### `open-fleet decisions` (native governance ledger & Ed25519 grants)

```text
open-fleet decisions [--file PATH] [--doors PATH] [--pin-ref REF] append --id ID --class mechanical|taste|one-way --answer A --why W [--task T] [--source human:<name>] [--grant-sig HEX] [--ts ISO]
open-fleet decisions [--file PATH] [--pin-ref REF] active [--json]
open-fleet decisions [--file PATH] tally --lens LENS [--json]
open-fleet decisions [--file PATH] [--doors PATH] [--pin-ref REF] check [--since YYYY-MM-DD] [--base REF]
open-fleet decisions grant-keygen --out PATH [--in-repo-ok]
open-fleet decisions sign-grant --key PATH --id ID --answer A --why W [--task T] [--source human:<name>] [--ts ISO]
```

- Exact parity with `runtime/scripts/decisions.py` using native `ed25519-dalek` signing and verification.
- Exit codes: `0` ok, `1` validation/custody refusal, `2` could not run / usage.

### `open-fleet missions | route | show | certification | overview | mcp` (native catalog & zero-Python MCP server)

```text
open-fleet missions [--proof external-run|self-run|doctrine-only] [--category CAT] [--repo DIR] [--json]
open-fleet route <goal>... [--top-k 5] [--repo DIR] [--json]
open-fleet show <mission> [--body] [--repo DIR] [--json]
open-fleet certification [--provider NAME] [--repo DIR] [--json]
open-fleet overview [--repo DIR] [--json]
open-fleet mcp [--root DIR] [--repo DIR]
```

- `open-fleet mcp` serves MCP JSON-RPC 2.0 over stdio (both newline-delimited JSON-RPC and `Content-Length` LSP framing, protocol versions `2025-03-26` and `2024-11-05`) with zero Python startup overhead for all 23 native tools (`fleet_doctor`, `fleet_route_mission`, `fleet_list_missions`, `fleet_get_mission`, `fleet_floor_check`, `fleet_certification`, `fleet_decisions`, `fleet_egress_verify`, `fleet_diff_scope`, `fleet_quarantine_check`, `fleet_proof_status`, `fleet_preflight`, `fleet_chain_check`, `fleet_session_start`, `fleet_session_list`, `fleet_session_packet`, `fleet_session_approve_gate`, `fleet_session_advance`, `fleet_solo_review`, `fleet_readiness`, `fleet_verify_manifest`, `fleet_run_report_check`, `fleet_events_report`), resources, and prompts.

### `open-fleet diff-scope | quarantine | dispatch-sign | inventory | proof-status` (Wave 2B-1 native verification suite)

```text
open-fleet diff-scope [--base REF] [--repo DIR] [--strict] [--overlap SPEC] [--predict-merge BASE BRANCH] [--json]
open-fleet quarantine [--root DIR] (--catalog | --mission NAME)
open-fleet dispatch-sign (gen-key | sign | verify | sign-transcript) ...
open-fleet inventory (write | check | sign | receipt) <report> ...
open-fleet proof-status [--json] [--check] [--root DIR]
```

- `diff-scope`: exact parity with `runtime/scripts/diff_scope.py` (all 12 `SCOPE_*` path + 256 KiB content rules, isolated git custody diffs, zero-segment globstar `--overlap`, shared-object-custody `git merge-tree --write-tree` `--predict-merge` with PEP 383 non-UTF-8 JSON encoding, shell-safe comment escaping). Exits `0` classified/clean merge, `1` real merge conflict, `2` `SCOPE_ERROR`.
- `quarantine`: exact parity with `runtime/scripts/quarantine_check.py` (human-only `by` validation, transitive `protocol_closure`, catalog & single-mission bundle layouts, `pins.json` verification). Exits `0` clean, `2` quarantined violation, `3` cannot evaluate.
- `dispatch-sign`: exact parity with `runtime/scripts/dispatch-sign.py` (Ed25519 keygen/sign/verify/sign-transcript, `0600` + off-unignored-worktree seed custody, monotonic `ro <= rw <= danger` profile narrowing, `#784` profile binding, sibling `toolchain.files` SHA-256 verification).
- `inventory`: exact parity with `runtime/scripts/inventory.py` (`#784` Markdown fence tracking and symlink-free path containment, fenced & table blocks, `--at REV` blob hashing, Ed25519 detached signatures, v1 retention receipts). Exits `0` verified, `1` mismatch/refusal, `2` could not run.
- `proof-status`: exact parity with `runtime/scripts/proof_status.py` (catalog proof-tier summary, repo-containment check on `proof_evidence`, `--json`, `--check`).

### `open-fleet preflight | chain-check | session | solo-review | ci-check | readiness` (Wave 3B native product & control suite)

```text
open-fleet preflight [--provider auto|orca|posix] [--mission NAME] [--base REF] [--mode mutate|readonly] [--offline] [--require-gitleaks] [--strict-native-capabilities] [--json]
open-fleet chain-check (classify <TERMINAL> | gate --allowed CSV <TERMINAL> | audit [--root DIR])
open-fleet session (start | list | packet | approve | advance | benchmark) ...
open-fleet solo-review [--base REF] [--repo DIR] [--contract PATH] [--builder HARNESS] [--lighting auto|dark|lit] [--packet-out PATH] [--json]
open-fleet ci-check [--base REF] [--repo DIR] [--strict-scope] [--fail-on-risk-lenses] [--workflow-snippet] [--json]
open-fleet readiness [--repo DIR] [--check-cert] [--probes] [--json]
```

- `preflight`: exact parity with `runtime/scripts/preflight.py` (provider resolution, capabilities matrix verification, quarantine check, canonical BASE != default branch check, fork-point & same-tip diagnostics; unknown/usage flags exit `1`, failed invariants exit `2`).
- `chain-check`: exact parity with `runtime/scripts/chain_check.py` (fail-closed degraded terminal classification, chain boundary gate, full catalog terminal audit).
- `session`: native progressive (<5K-token/phase) mission state machines with atomic JSON writes, enforced human one-way doors, receipt checks, and context-savings benchmark (`session benchmark`).
- `solo-review`, `ci-check`, `readiness`: native in-process composition over `of-floor`, `of-verify::diff_scope`, and native `open-fleet verify` (zero Python startup across the entire review/CI/readiness pipeline).

### `open-fleet verify | run-report | events` (Wave 2B-2 native proof verifier, run-report binder & events ledger)

```text
open-fleet verify --manifest PATH [--contract-source S] [--contract-digest D] [--unit-class C] [--base REF] [--repo OWNER/NAME] [--execute-nc --nc-command CMD | --allow-static-nc] [--lighting lit|dark-eligible] [--lane A|B|0] [--no-gh] [--dispatch-record F --dispatch-pubkey K] [--git-dir DIR] [--evidence-root DIR] [--retention-pubkey K] [--transcript-out F] [--transcript-key K]
open-fleet run-report [REPORT] [--mission M] [--tier self-run|external-run] [--base REV] [--root DIR] [--json]
open-fleet events [--log PATH] (emit | ingest-state | ingest-launch | ingest-merge-queue | ingest-transcript | ingest-usage | verify | report | check) ...
```

- `verify`: exact parity with `runtime/scripts/verify.py` (`_verify_sig.py` + `_verify_diff.py`): fail-closed git/gh custody pinning, denominator & hidden-criterion extraction, oracle-scope enforcement, real-commit/ancestry/base-binding, Ed25519 signed dispatch provenance, content-bound commands ledger, built-in + gitleaks redaction, intent/lighting/reviewer-mode/provenance/retention-receipt checks, isolated 3-phase `clean -> control -> clean` `--execute-nc` runner with `#750 C19` command-grammar & executable identity pinning, and Ed25519 signed transcripts with W3-11 toolchain drift checks. Pinned to **0% false-done and 0% false-reject on VF-Bench** (`scripts/rust_verify_oracle.py`). Exits `0` GREEN, `2` RED/invariant failure, `1` usage/dependency error.
- `run-report`: exact parity with `runtime/scripts/run_report.py`: `RUN:` header parsing, manifest containment, inventory re-hashing at pinned commits, signed transcript & signed inventory verification against trusted bases, sound-lane enforcement, and CommonMark-aware WIP-curve checks (`scripts/rust_run_report_oracle.py`, 85 tests). Exits `0` bound, `1` not bound, `2` could-not-run.
- `events`: exact parity with `runtime/scripts/events.py`: append-only JSONL ledger with `flock` locking, secret redaction, read-only bundled-SQLite `ingest-state` (`rusqlite`, never creates `-wal`/`-shm`), launch/merge-queue/transcript/usage ingestion, exact rational (`Frac`) WIP-curve derivation with `ROUND_HALF_EVEN` formatting, and Markdown/JSON reporting (`scripts/rust_events_oracle.py`, 98 tests). Exits `0` ok, `1` incomplete/mismatch, `2` usage, `3` fail-closed.

### `open-fleet hook --mode deny` / `open-fleet deny-hook` (Wave 1.5 native PreToolUse guardrail)

```text
open-fleet deny-hook [--help | --settings <WORKTREE> [--readonly] | --verify-settings <FILE> [--harness NAME] [--boundary DIR] [--readonly]]
open-fleet hook --mode deny [ARGS...]
```

- Exact parity with `runtime/scripts/deny-hook.sh` (6,825 LOC) with zero shell/Python startup overhead:
  - Quote-aware shell lexer, brace expander (`cap=512/4096`), single-pass substitution/heredoc/arithmetic/bracket analyzer, wrapper/launcher/busybox command peeler, nested body & interpreter extractors, 4-round stdin/pipe/heredoc/fd-dup dataflow analyzer.
  - Full HIGH-tier enforcement (`rm` root/NPR, `git push` with git-2.43 prefix table + F4 per-ref `--force-with-lease` + default-branch resolution, `orca orchestration reset`, unreceipted off-repo egress gate, git/gh alias & exec-config laundering, awk `-f/-E`).
  - Self-guard over all harness hook configs, `.orca/*-pubkey` trust anchors, and `deny-hook.sh` / `open-fleet` itself; read-only (`ro`) write floor; 32-hop symlink & 64-match glob worktree boundary check; Never-list + 14 ERE regexes.
  - Native `rusqlite` WAL file-touch conflict recorder (`SCHEMA_VERSION=2` compatible with `LocalStateStore`) with coordinator escalations.
  - Multi-harness `--settings` & `--verify-settings` across all 11 supported harnesses (`claude`, `codex`, `openhands`, `goose`, `crush`, `hermes`, `opencode`, `omp`, `pi`, `jcode`, `generic`) with SHA-256 identity, C18 interpreter custody walk, and live scrubbed probes.
- Pinned byte-for-byte via `scripts/rust_deny_hook_oracle.py` (**398/398 tests** across `test_deny_hook.py`, `test_deny_hook_multi_harness.py`, `test_deny_hook_conformance.py`, and `test_trajectory_evals.py`). Exits `0` on allow / Claude-mode JSON verdict, `2` on strict-mode deny / unreadable payload / CLI usage or `--verify-settings` refusal.

### `open-fleet ui | demo | status` & Binary-Bound Provenance (Phase B/C `v1.0.0`)

```text
open-fleet ui [--host 127.0.0.1] [--port 8765] [--repo DIR]
open-fleet demo [--json]
open-fleet status [--repo DIR] [--db PATH] [--json]
open-fleet mcp [--root DIR] [--repo DIR] [--print-config HARNESS] [--runtime auto]
```

- `open-fleet ui`: serves the Mission Control HTML cockpit (from the checkout or compile-time embedded `open_fleet/ui_assets/index.html`) plus all `/api/*` JSON & `/api/events/stream` SSE endpoints over stdlib `TcpListener` with zero Python runtime and zero external HTTP crate dependencies.
- `open-fleet demo`: runs the head-to-head negative-control scope-shrink trap natively in an ephemeral temp repo (`selfscore: GREEN (exit 0)` vs independent `open-fleet verify` `RED (exit 2)` naming dropped `AC-2`), zero Python and zero repo clone required.
- `open-fleet status`: inspects the catalog overview plus live read-only `.orca/runtime.db` SQLite tables (`runs`, `tasks`, `dispatches`, `gates`, `mq_entries`), events, egress, and `docs/DECISIONS.md` without creating `-wal`/`-shm` files.
- **Binary-bound transcripts (`v1.0.0`):** `open-fleet verify --transcript-out ...` binds `toolchain.engine = "rust"`, `toolchain.engine_version`, and `toolchain.engine_binary_sha256` into the signed Ed25519 verdict payload and checks mid-run binary drift (W3-11). `open-fleet dispatch-sign sign-transcript` re-hashes the running binary and refuses mismatches fail-closed, enabling standalone zero-clone signed verification outside any git checkout.

### Strangler-Fig Pass-Through Verbs (Deferred / Kept in Python)

The remaining catalog-only developer utilities cleanly locate the repository root and exec the canonical Python implementation:
- `open-fleet queue|upstream-probe ...` — passes through to `runtime/scripts/<tool>.py`.
