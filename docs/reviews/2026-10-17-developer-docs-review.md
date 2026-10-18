# Developer Documentation Deep Review & Claim Audit (2026-10-17)

**Scope:** Full developer-perspective documentation review across `orca-fleet` at `v1.4.229`, combining the [`document-it`](../../skills/document-it/SKILL.md) Diátaxis coverage protocol ([`playbooks/doc-coverage.md`](../../playbooks/doc-coverage.md)) with [`clean-sweep`](../../skills/clean-sweep/SKILL.md) `source=doc-claims` verification against live code, CLI `--help` surfaces, and JSON schemas.

---

## 1. Executive Summary

A developer arriving at `orca-fleet` traverses five primary journeys:

1. **Install & wire the completion gate** ([`docs/install.md`](../install.md), [`docs/verify-gate.md`](../verify-gate.md))
2. **Run a first mission (`review-it` → `ship-it`)** ([`docs/getting-started.md`](../getting-started.md))
3. **Select a mission & copy a prompt recipe** ([`docs/missions/README.md`](../missions/README.md), [`docs/recipes.md`](../recipes.md))
4. **Look up a runtime helper's flags, subcommands, keys, or exit codes** ([`docs/runtime-scripts.md`](../runtime-scripts.md))
5. **Contribute to the catalog & run local/CI verification gates** ([`docs/development.md`](../development.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md), [`docs/troubleshooting.md`](../troubleshooting.md))

Running the authoritative surface extractor (`extract.py`), the Diátaxis quadrant mapper (`map.py`), and the claim binder (`claimcheck.py`) against the live 81-entity repository surface (`22` skills, `51` CLIs/libraries, `8` config registries) surfaced **12 unbound claims**, **5 missing reference sections**, **1 alphabetical ordering inversion**, and **3 developer-guide drift items** relative to the `v1.4.229` runtime pin and `#560` (`VAL-01`) prompt-injection drill suite. All findings have been remediated and machine-verified (`34 section(s), 0 unbound claim(s)`).

---

## 2. Surface Extraction & Diátaxis Quadrant Audit (81 Entities)

| Sub-surface | Count | Reference (`REF`) | How-To (`HOW`) | Tutorial (`TUT`) | Explanation (`EXP`) | Status after remediation |
|---|---:|---|---|---|---|---|
| **A — Missions (`skills/*/SKILL.md`)** | 22 | `docs/missions/<name>.md` + `README.md` | `docs/missions/<name>.md` + `docs/recipes.md` | `docs/getting-started.md` (`review-it`, `ship-it`) | `docs/missions/<name>.md` (`Why` + failure modes) | **22 / 22 covered (0 gaps)** |
| **B — Runtime CLIs & libraries (`runtime/scripts/*`)** | 38 | `docs/runtime-scripts.md` + `docs/verify-gate.md` | `docs/run-submission-guide.md` + `docs/verify-gate.md` | `docs/getting-started.md` | `docs/runtime-scripts.md` (`> Why:` blocks) | **38 / 38 covered (0 gaps)** |
| **B — Catalog & CI scripts (`scripts/*`, `hooks/*`)** | 13 | `docs/development.md` + `docs/ops.md` + `docs/release-1.0-checklist.md` | `docs/development.md` + `docs/ops.md` | `docs/getting-started.md` (`print-settings-snippet.sh`) | `docs/verify-gate.md` + `docs/ops.md` | **13 / 13 covered (0 gaps)** |
| **C — Operator & repo configs (`runtime/*.json`, `hooks/*.json`, `.env.example`, `ruff.toml`)** | 8 | `docs/runtime-scripts.md` + `docs/verify-gate.md` + `docs/development.md` | `docs/install.md` + `docs/development.md` | `docs/getting-started.md` | `docs/runtime-scripts.md` (`> Why:` blocks) | **8 / 8 covered (0 gaps)** |

---

## 3. Defects Found & Remediated

### 3.1 Twelve Unbound Factual Claims in `docs/runtime-scripts.md`

When `claimcheck.py` evaluated `docs/runtime-scripts.md` against the live surface, 12 claims failed to bind to authoritative repository paths or CLI `--help` + source tokens:

| # | Section in `docs/runtime-scripts.md` | Unbound claim reported by `claimcheck.py` | Root cause | Fix landed |
|---|---|---|---|---|
| 1 | `## hitl-loop.template.sh` | `PATH hitl_ask.py does not exist` | Used bare `` `hitl_ask.py` `` instead of repo-relative path | Anchored as `` `runtime/scripts/hitl_ask.py` `` |
| 2 | `## orca_cli.py` | `PATH check_reply.py does not exist` | Used bare `` `check_reply.py` `` | Anchored as `` `runtime/scripts/check_reply.py` `` |
| 3 | `## orca_cli.py` | `PATH hitl_ask.py does not exist` | Used bare `` `hitl_ask.py` `` | Anchored as `` `runtime/scripts/hitl_ask.py` `` |
| 4 | `## orca_cli.py` | `PATH skill-stubs/_shared/cli-resolution.md does not exist` | Backticked an upstream `stablyai/orca` path ending in `.md`, triggering `PATH_RE` repo-existence check | Formatted as upstream path reference without local-path backticks |
| 5 | `## orca_cli.py` | `PATH spawn_worker.sh does not exist` | Used bare `` `spawn_worker.sh` `` | Anchored as `` `runtime/scripts/spawn_worker.sh` `` |
| 6 | `## quarantine_check.py` | `PATH decisions.py does not exist` | Used bare `` `decisions.py` `` | Anchored as `` `runtime/scripts/decisions.py` `` |
| 7 | `## spawn_worker.sh` | `PATH deny-hook.sh does not exist` | Used bare `` `deny-hook.sh` `` | Anchored as `` `runtime/scripts/deny-hook.sh` `` |
| 8 | `## task_ops.py` | `SUBCOMMAND create --spec TEXT [...] not in help+source` | `Subcommands:` line wrapped the full flag synopsis inside backticks instead of backticking subcommand names | Split into `Subcommands: \`create\`, \`update\`.` and a separate `Flags:` paragraph |
| 9 | `## terminal_ops.py` | `SUBCOMMAND create [--worktree W] [...] not in help+source` | Same synopsis-in-backticks issue on `Subcommands:` line | Split into `Subcommands: \`create\`, \`read\`, \`list\`, \`show\`.` and `Flags:` |
| 10 | `## worker_ops.py` | `SUBCOMMAND show --dispatch D not in help+source` | Same synopsis-in-backticks issue on `Subcommands:` line | Split into `Subcommands: \`show\`, \`read\`, \`stop\`, \`abandon\`, \`release\`, \`retain\`, \`list\`.` and `Flags:` |
| 11 | `## worktree_ops.py` | `SUBCOMMAND list [--repo SELECTOR] [--limit N] not in help+source` | Same synopsis-in-backticks issue on `Subcommands:` line | Split into `Subcommands: \`list\`, \`show\`.` and `Flags:` |
| 12 | `## worktree_ops.py` | `SUBCOMMAND show --worktree SELECTOR not in help+source` | Same synopsis-in-backticks issue on `Subcommands:` line | Covered by the `Subcommands:` / `Flags:` split above |

### 3.2 Five Missing Reference Sections & Ordering Fix in `docs/runtime-scripts.md`

Five runtime modules/configs added after the initial 2026-09-16 `document-it` campaign had no `## \`<name>\`` reference section in `docs/runtime-scripts.md`:

1. **`## \`_verify_sig.py\``** — Control-outcome reader behind `verify.py`'s executed negative control (`_counted`, `_failure_signature`, `STILLBORN_MARKERS`, `STRONG_ASSERTION_RE`), carved out by `reshape-it` (`RV-D2`).
2. **`## \`chain_check.py\``** — Executable degraded-terminal classifier and step gate for sequential mission chains (`classify`, `gate --allowed`, `audit --root`), pinned by `tests/test_chain_check.py`. Also added to the top `## Find a helper` table and category index.
3. **`## \`diffparse.py\``** — Hunk-counted unified-diff reader (`records`, `HUNK`, `NO_NEWLINE`) shared by `floor_guard.py` and `verify.py` so removed/added lines starting with `-- ` or `++ ` cannot spoof file headers.
4. **`## \`gitexec.py\``** — Single git binary resolver (`GIT`, `GitAbsent`, `argv`) and hardened environment (`env`: `GIT_NO_REPLACE_OBJECTS=1`, `core.fsmonitor=false`, `protocol.ext.allow=never`) for read-side tools (`inventory.py`, `evidence-run.py`, `floor_guard.py`, `preflight.py`).
5. **`## \`pins.json\``** — Upstream pin registry (`_about`, `orca`, `gstack`, `addyosmani`, `mattpocock`), documenting the schema, witness modes (`live` vs `source`), and rug-pull review requirement enforced by `tests/test_pins.py`.
6. **Alphabetical section order & category index:** Reordered `## \`pin_review.py\`` before `## \`pm.py\`` and `## \`quarantine_check.py\``, and added missing category-index links at the top of `docs/runtime-scripts.md`.

### 3.3 Developer Onboarding & Contributor Guide Updates (`v1.4.229` & `VAL-01`)

- **[`docs/getting-started.md`](../getting-started.md), [`skills/clean-sweep/SKILL.md`](../../skills/clean-sweep/SKILL.md), and [`docs/missions/clean-sweep.md`](../missions/clean-sweep.md):** Updated tracker prerequisite rows and `clean-sweep`'s `compatibility` / `Needs` line to name `orca jira` alongside `orca linear` (matching `README.md`, `docs/concepts.md`, and `playbooks/linear-enumeration.md` at `v1.4.229`).
- **[`docs/runtime-scripts.md`](../runtime-scripts.md) (`## \`guard_text.py\``) & [`docs/development.md`](../development.md):** Linked the deterministic `VAL-01` prompt-injection drill suite (`evals/injection-drills.json`, `tests/test_injection_drills.py`, `python3 scripts/eval.py run --suite injection`) alongside `tests/fixtures/injection.json`, and added references to `scripts/release_check.py`, `scripts/_countlint.py`, `scripts/_identity.py`, `.env.example`, and `ruff.toml` in `docs/development.md`.

---

## 4. Developer Journey Walkthrough Verdict

| Developer persona & task | Entry doc | Path verified | Verdict |
|---|---|---|---|
| **Evaluator** installing the catalog & completion hook | [`docs/install.md`](../install.md) | Decision table → symlink (`sh scripts/install.sh`) vs plugin (`/plugin marketplace add`) → hook wiring (`sh hooks/print-settings-snippet.sh --check`) → rollback/uninstall | **PASS** — install-vs-run prerequisite classes and `v1.4.229` floor match `runtime/pins.json`. |
| **First-time user** running `review-it` and `ship-it` | [`docs/getting-started.md`](../getting-started.md) | `orca status --json` readiness check → `orca linear` / `orca jira` tracker support → `review-it` read-only dry run → `ship-it` promotion PR flow → cost & human gates | **PASS** — all CLI commands, links, and diagram embeds verified. |
| **Practitioner** picking a mission & prompt | [`docs/missions/README.md`](../missions/README.md) · [`docs/recipes.md`](../recipes.md) | 16-row task selector + 22 mission guides + 8 copy-paste prompt recipes (`review-it`, `ship-it`, `clean-sweep`, `root-cause`, `prove-it`, `modernize-it`, `document-it`, `speed-it`) | **PASS** — every mission guide's `Needs` line matches `SKILL.md` `compatibility` verbatim. |
| **Coordinator / integrator** looking up runtime CLIs & configs | [`docs/runtime-scripts.md`](../runtime-scripts.md) · [`docs/verify-gate.md`](../verify-gate.md) | `## Find a helper` task table + 34 source-anchored `##` reference sections (`Usage`, `Subcommands`, `Flags`, `API`, `Keys`, `Exits`, `> Why`) | **PASS** — `claimcheck.py` binds all 34 sections with 0 unbound claims. |
| **Contributor** editing skills, docs, or runtime scripts | [`docs/development.md`](../development.md) · [`docs/troubleshooting.md`](../troubleshooting.md) | Local setup → `Find the right file` table → `Everyday checks` (`validate.py`, `gen-badges.py --check`, `eval.py`, `bundle.py --check`, `release_check.py`, `shard-tests.py`) | **PASS** — every local and CI check command is documented and runnable. |
