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

- Installs canonical `skills/` into each selected harness's native skills directory.
- With `--with-hooks` (default on `init`), atomically merges the native `open-fleet floor` Stop/TaskCompleted guard into Claude Code `settings.json` without clobbering existing user hooks.
- Exits `0` on success, `2` on usage or unreadable source/target errors.

### Strangler-Fig Pass-Through Verbs (Waves 2–4)

Until ported natively into `crates/`, the following verbs cleanly locate the repository root and
exec the canonical Python/shell implementation with identical arguments and exit codes:
- `open-fleet hook ...` — supports native `--mode floor` now; passes through full pre-tool shell policy to `runtime/scripts/deny-hook.sh` (Wave 1.5).
- `open-fleet verify|egress|decisions|events|mcp|ui|missions|run|queue ...` — passes through to `python3 -m open_fleet` or `runtime/scripts/<tool>.py` (Waves 2–3).
