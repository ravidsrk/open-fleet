# Runtime scripts and operator config — reference

[Documentation](README.md) · [Local development](development.md) · [Completion gate](verify-gate.md)

Use this page to find the helper behind an operation, then check its usage, flags and exits.
The helpers live in `runtime/scripts/`; operator registries live in `runtime/`.
Every section anchors to its source file (read the implementation, not this page,
when they disagree) and to the test that pins its behavior. Claim-checked by
`docs/runs/campaign-2026-09-16-document-it/extractor/claimcheck.py`.

Paths below are relative to the catalog clone. A helper that operates on a project must
run with that project's working directory or its documented repository argument; a relative
manifest or ledger path resolves in the invocation's working directory. Read the individual
helper's defaults before running it. For catalog-only checks, use [Development](development.md).

## Find a helper

The verification tools have dedicated guides; start there for the required inputs and trust
boundary rather than assembling a gate command from its flags alone.

| I need to… | Helper | Guide |
|---|---|---|
| Check a run's base and dependencies | [`preflight.py`](../runtime/scripts/preflight.py) | [BASE in the glossary](concepts.md#glossary), plus the helper's usage header |
| Block a compromised component fleet-wide | [`quarantine_check.py`](#quarantine_checkpy) | [`quarantine.json`](#quarantinejson), plus the section below |
| Classify or gate a mission-chain step | [`chain_check.py`](#chain_checkpy) | [Chaining missions](concepts.md#chaining-missions) and [`mission-chaining.md`](../runtime/mission-chaining.md) |
| Record a test or verifier command in a manifest | [`evidence-run.py`](../runtime/scripts/evidence-run.py) | [Run submission, step by step](run-submission-guide.md#step-by-step) |
| Verify a unit's evidence | [`verify.py`](../runtime/scripts/verify.py) | [Gate inputs](verify-gate.md#native-path--plugin-hooks-set-claude_plugin_root) and [manifest policy](../runtime/evidence-manifest.md) |
| Connect verification to completion events | [`verify-gate.sh`](../runtime/scripts/verify-gate.sh) | [Install paths](verify-gate.md#install-paths-and-which-ones-carry-the-gate) |
| Sign a coordinator-owned dispatch | [`dispatch-sign.py`](../runtime/scripts/dispatch-sign.py) | [Signed dispatch](verify-gate.md#signed-dispatch--what-it-binds-and-where-the-key-comes-from-135) |
| Write or check an artifact inventory | [`inventory.py`](../runtime/scripts/inventory.py) | [Run submission](run-submission-guide.md#step-by-step); recheck history at the report's named commit |
| Check whether a run report binds | [`run_report.py`](../runtime/scripts/run_report.py) | [What binding means](run-submission-guide.md#what-binding-means) |
| Read the catalog's proof tiers | [`proof_status.py`](../runtime/scripts/proof_status.py) | [Proof status](concepts.md#proof-status) |
| Review a pack pin bump for rug-pulls | [`pin_review.py`](#pin_reviewpy) | [Pack pin bumps](../runtime/orca-pin.md#pack-pin-bumps-carry-a-rug-pull-review-559), [`pins.json`](#pinsjson), plus the section below |

The remaining reference sections cover:

- **Messages and human decisions:** [check/reply](#check_replypy), [inbox parsing](#pmpy),
  [sending](#send_msgpy), [decision log](#decisionspy), [human asks](#hitl_askpy),
  [ask/reply loop](#hitl-looptemplatesh), [gate batches](#gate-batchpy),
  [one-way door registry](#one-way-doorsjson).
- **Workers and workspace operations:** [spawn](#spawn_workersh), [workers](#worker_opspy),
  [tasks](#task_opspy), [terminals](#terminal_opspy), [worktrees](#worktree_opspy),
  [working-tree fingerprints](#wtreesh), [session search](#search_sessionspy),
  [chain gate](#chain_checkpy).
- **Guards and sandbox checks:** [tool guard](#deny-hooksh), [visible-text guard](#guard_textpy),
  [change scope](#diff_scopepy), [quality floor](#floor_guardpy), [sandbox doctor](#sandbox_doctorpy),
  [egress receipts](#egresspy), [component quarantine](#quarantine_checkpy),
  [quarantine registry](#quarantinejson).
- **Runtime compatibility and liveness:** [CLI adapter](#orca_clipy), [upstream probe](#upstream_probepy),
  [pin rug-pull review](#pin_reviewpy), [upstream pin registry](#pinsjson),
  [watchdog](#watchdogpy), [watchdog registry](#watchdogjson).
- **Signing and internal primitives:** [Ed25519 library](#ed25519py),
  [control-outcome reader](#_verify_sigpy), [hunk-counted diff parser](#diffparsepy),
  [hardened git executor](#gitexecpy).

## `_verify_sig.py`

Control-outcome reader behind `runtime/scripts/verify.py`'s executed negative control —
separates an evaluated assertion failure (a killed mutant) from a stillborn mutant (an import,
syntax, or collection error that died before the oracle ran). Private import-only library (moved
here by reshape-it `RV-D2`; import through `runtime/scripts/verify.py`, never directly). Source
`runtime/scripts/_verify_sig.py:1-6`; behavior pinned by `tests/test_reshape_net_verify.py` and
`tests/test_reshape_width_verify.py`.

API: `_counted`, `_failure_signature`.

`_counted(pattern, text)` sums integer runner counts matched across `text` (returning `None`
when no summary line matched); `_failure_signature(stdout, stderr)` returns `(ok, reason)`,
requiring output, rejecting error-only summaries (`FAILED (errors=1)` with zero failures), and
refusing stillborn tracebacks unless a strong assertion marker overrides them.

Exits: n/a (library).

> Why: a negative control that breaks an import or introduces a syntax error exits non-zero for
> any command at all — it never exercised the test suite. The module pairs
> `runtime/scripts/_verify_sig.py:STILLBORN_MARKERS` and `runtime/scripts/_verify_sig.py:_ERRORS_RE`
> against `runtime/scripts/_verify_sig.py:ASSERTION_MARKERS`,
> `runtime/scripts/_verify_sig.py:STRONG_ASSERTION_RE`, and
> `runtime/scripts/_verify_sig.py:_FAILURES_RE` so only a failure where an assertion was actually
> evaluated counts as a kill.

## `chain_check.py`

Executable form of `runtime/mission-chaining.md`'s degraded-terminal stop rule: classifies a
mission terminal as `clean`, `degraded`, or `handoff`, gates whether a sequential chain may
advance to its next step, and audits the catalog's `skills/*/SKILL.md` terminal labels against
the classification rule. Source `runtime/scripts/chain_check.py:1-19`; behavior pinned by
`tests/test_chain_check.py`.

Usage: `chain_check.py {classify,gate,audit} ...`

Subcommands: `classify`, `gate`, `audit`.

Flags: `gate` takes `--allowed` (required comma-separated list of terminal states the chain
contract declared allowed to advance); `audit` takes `--root` (catalog root directory, default
repo root).

API: `classify`, `gate`, `audit`.

`classify` prints `clean`, `degraded`, or `handoff` for a terminal name; `gate` prints `PROCEED`
(exit 0) only when the terminal is not degraded AND appears in `--allowed`, otherwise `STOP <why>`
(exit 1); `audit` checks every bold terminal in `skills/*/SKILL.md` so degraded terminals carry
the `(degraded)` label and clean/handoff terminals do not.

Exits: 0 ok or proceed · 1 stop (`STOP`) or catalog audit mismatch · 2 usage or could-not-run.

> Why: before this script, the degraded-terminal rule lived in prose and missed `ABANDONED`
> (`migrate-it`'s rolled-back terminal), letting a failed migration leg read as clean. Putting
> `runtime/scripts/chain_check.py:DEGRADED_SUFFIXES`,
> `runtime/scripts/chain_check.py:DEGRADED_STANDALONE`, and
> `runtime/scripts/chain_check.py:HANDOFF` in one executable module — and checking every
> `skills/*/SKILL.md` against `runtime/scripts/chain_check.py:_TERMINAL_RE` via `audit` — makes
> an unlabelled degraded terminal fail validation before a chain ever runs.

## `check_reply.py`

Fail-closed invoker for `check` and `reply` — pm.py parses the inbox, this issues
it. Source `runtime/scripts/check_reply.py:1-21`; behavior pinned by
`tests/test_check_reply.py`.

Usage: `check_reply.py {check,reply} ...`

Subcommands: `check` (a terminal's messages), `reply` (one message).

Flags: `check` takes `--terminal`, `--run`, `--ack`, one read mode (`--unread`,
`--peek`, `--all`), `--types` (orchestration message keyset), `--format`, `--wait`,
`--timeout-ms` (positive int), `--retry-request`; `reply` takes `--id`, `--body`,
`--run`, `--from`, `--retry-request`. `--from` defaults to `ORCA_TERMINAL_HANDLE`;
an explicit `--from` that disagrees with it is refused.

A `--wait` that times out (`timedOut`) is exit 0 with `TIMED_OUT=yes`, not a failure.

Each message prints as a `--- <id> (<type>) from <handle>` block with `SUBJ:` and
the body (capped at 2000 chars with a truncation marker); malformed entries skip
with a stderr WARN. Consuming reads show what they consumed — a later check may
never see these messages again. Every printed field passes through pm.py's
`_visible`, so control and invisible characters render inertly, never actively.

Exits: 0 checked/replied · 1 runtime/refusal/receipt failure · 2 usage or
validation refusal (nothing invoked).

> Why: at most one read mode, because the handler refuses more — and on older
> runtimes an unknown `--peek` strips while `--unread` still marks read, so a
> combined read would destroy what it meant to preview. Naming the sender is an
> identity claim: a wrong `--from` speaks as a sibling worker, so disagreement with
> the ambient handle refuses rather than misattributes.

## `decisions.py`

Writer, reader, and validator for the DECISIONS log (`docs/DECISIONS.md`). Source
`runtime/scripts/decisions.py:1-63`; behavior pinned by `tests/test_decisions.py`.

Usage: `python3 runtime/scripts/decisions.py [--file PATH] [--doors PATH] <subcommand> ...`

Subcommands: `append`, `active`, `tally`, `check`.

Flags: `--file` (log path, default `docs/DECISIONS.md`), `--doors` (door registry,
default `runtime/one-way-doors.json`). `append` takes `--id`, `--class`, `--answer`,
`--why`, `--task`, `--source`, `--ts`; `tally` takes `--lens`, `--json`.

Log line format: `ts · gate-or-ask-id · class · answer · why · task?` with classes
`mechanical`, `taste`, `one-way`. `append` refuses unknown classes, empty id/answer/why,
fields containing `·` or newlines, credential-shaped values, lines tripping the one-way
keyword net without class `one-way`, and `one-way` lines without `source=human:<name>`
(via `--source`). `active` lists non-superseded lines (newest per id wins; an answer of
exactly `superseded` retires the id). `tally --lens <name>` reports the consecutive
zero-finding streak for `lens-tally:<lens>` lines and whether the lens may auto-gate off
(10+ zeros, never for `security`, `privacy`, `data-migration`).

Exits: 0 ok · 1 validation failure · 2 could-not-run.

> Why: the log was a parser without a writer — hand-typed lines let two coordinators
> disagree about the same record. `append` refuses reclassification by wording (the net
> is built from the registry at `runtime/scripts/decisions.py:load_doors`) and demands a
> human source for one-way lines (`runtime/scripts/decisions.py:HUMAN_SOURCE`). Tallies
> live in committed state so a crashed run's gate verdict survives, and the `security`,
> `privacy`, `data-migration` lenses never gate off
> (`runtime/scripts/decisions.py:NEVER_GATE`): their value is the miss they would catch —
> a policy naming three and a gate enforcing two is how privacy silently switched itself
> off (PR #277 review).

## `deny-hook.sh`

PreToolUse guard for read-write workers (Bash, Edit, Write). Reads the hook event JSON
on stdin, writes one decision object on stdout. Source `runtime/scripts/deny-hook.sh:1-108`;
behavior pinned by `tests/test_deny_hook.py`.

Usage: hook mode reads stdin (no arguments); `deny-hook.sh --settings <worktree>` prints
the settings.json registration block with the worktree boundary resolved.

Flags: `--help`, `--settings`.

HIGH tier denies (never asks) for Bash: recursive delete rooted at `/`, `~`, `$HOME`, or
`/*` (or carrying `--no-preserve-root`); force-push to the default branch (including the
`+main` refspec and outright deletion forms); `git push --force` without an effective
`--force-with-lease`; `git push --mirror` and `--prune` (each deletes remote refs it never
names); `orca orchestration reset`; and an off-repo write (`gh pr|issue|release`
write verbs, or `gh api` with a write method/field) not preceded in the same command by
its `egress.py write` receipt (#561 — reads stay free; a receipt after the send does
not count). Push long options are read the way git reads them, so an unambiguous
abbreviation (`--del`, `--mi`, `--no-force-w`) is the option it expands to. An effective `--force-with-lease` exempts
a force-push but never a deletion. The Never list asks instead: live-prod mutation,
credential provisioning, destructive teardown, unpinned remote execution, publishing,
history-discarding local git. When `ORCA_UNIT_WORKTREE` is set, writes outside it deny —
Edit/Write `file_path`, NotebookEdit `notebook_path`, and absolute-path Bash redirects and
`tee` destinations — resolved through the full symlink chain.

Exits: always 0 in hook-decision mode — the decision is the output, not the status.
`--settings` exits 2 when the worktree is missing/invalid or python3 is absent; any other
argument exits 2 as well.

> Why: doctrine sits above the model and this sits below it — a read-write worker runs
> with prompts turned down, so the hook is the only thing between an improvised command
> and the disk. Polarity is fail-closed (unparseable input denies) and the decision
> nesting is load-bearing (`runtime/scripts/deny-hook.sh:permissionDecision` — a
> top-level decision is ignored, which is how a deny silently becomes an allow). HIGH
> denies what has no legitimate form while the Never list asks what does; the worktree
> boundary (`runtime/scripts/deny-hook.sh:ORCA_UNIT_WORKTREE`) resolves the full symlink
> chain because a worker that can run a shell can spell any write as a redirect.

## `diff_scope.py`

Fail-loud scope classification: which review lenses a change earns. Emits shell-safe
`SCOPE_<FLAG>=true|false` assignments (sourcable) or a JSON object. Source
`runtime/scripts/diff_scope.py:1-75`; behavior pinned by `tests/test_diff_scope.py`.

Usage: `diff_scope.py [--base REF] [--repo DIR] [--strict] [--overlap FILE] [--json]` (also sourcable as
`source <(diff_scope.py)`).

Flags: `--base` (default origin/HEAD, then origin/main, origin/master, main, master),
`--repo` (default `.`), `--strict` (any unmatched path exits nonzero), `--overlap`
(pre-dispatch JSON `{units: [{id, scope: [...]}]}` intersecting declared unit globs
against tracked repo files and pattern prefixes to emit `OVERLAP_COUNT` / `--deps`
serialization chains for shared hot files), `--json` (emit an object instead of shell
assignments).

Changed set = committed diff vs merge base + working tree + untracked files. Twelve
independent flags: `FRONTEND`, `BACKEND`, `PROMPTS`, `TESTS`, `DOCS`, `CONFIG`,
`MIGRATIONS`, `API`, `AUTH`, `SECURITY`, `A11Y`, `PERF` — path signals plus working-tree
content signals (capped at 256 KiB per file; deleted files contribute path signals only).
Only `BACKEND` is exclusive of frontend view files.

Exits: 0 classified · 2 SCOPE_ERROR=no_base|diff_failed|unmatched|invalid_overlap.

> Why: the failure mode that makes a scope gate worthless is silence — a shallow checkout
> resolves no base, the diff is empty, and a legitimate-looking zero is recorded. So the
> script distinguishes nothing-changed from could-not-look
> (`runtime/scripts/diff_scope.py:ScopeError`), and the changed set is a union including
> untracked files (`runtime/scripts/diff_scope.py:changed_files`) because a brand-new
> migration is exactly what a reviewer must see. Partial-match stays information, not
> failure, unless a lens opts into `--strict` — turning it into a failure by default would
> break every caller whose repo has a file the table has no rule for.

## `diffparse.py`

Hunk-counted unified-diff reader shared by the diff-reading guards (`runtime/scripts/floor_guard.py`
and `runtime/scripts/verify.py`). Import-only library — no CLI. Source
`runtime/scripts/diffparse.py:1-21`; behavior pinned by `tests/test_floor_guard.py` and
`tests/test_verify.py`.

API: `records`.

`records(diff_text)` yields `(kind, line, hunk_match)` tuples across `diff_text` (`header`, `hunk`,
`-`, `+`, `' '`, or `marker` for `\ No newline at end of file`), splitting strictly on `\n` and
raising `ValueError` on a malformed or truncated hunk.

Exits: n/a (library).

> Why: a unified diff cannot be read by line prefix alone — a removed content line starting with
> `-- ` becomes `--- …` on the wire, and an added `++ x` becomes `+++ x`, which lets content lines
> spoof file headers in a naive parser. Counting the old-side and new-side budgets declared by
> `runtime/scripts/diffparse.py:HUNK` (and matching `runtime/scripts/diffparse.py:NO_NEWLINE`
> explicitly) guarantees that every line inside a hunk is treated as content until both counts
> reach zero.

## `ed25519.py`

Vendored pure-Python Ed25519 (RFC 8032), dependency-free. Import-only library — no CLI.
Source `runtime/scripts/ed25519.py:1-21`; verified against the RFC 8032 test vectors in
`tests/test_ed25519.py`.

API: `publickey`, `signature`, `checkvalid`.

`publickey(seed)` derives the 32-byte public key for a 32-byte secret seed;
`signature(msg, seed, pub)` returns the 64-byte signature; `checkvalid(sig, msg, pub)`
returns True iff valid. Hardening beyond the bare reference: rejects non-canonical
`S >= L`, non-canonical point encodings, and small-order/identity public keys (cofactor
check). Not constant-time: signs and verifies tiny dispatch-provenance records only, never
bulk data or network secrets. Used by `runtime/scripts/dispatch-sign.py` (sign, off the
graded worker) and `runtime/scripts/verify.py` (verify at the gate).

Exits: n/a (library).

> Why: the gate runs as a completion hook in arbitrary sandboxes where `pip install` may
> not be possible, so the whole gate is stdlib-only — this module's only import is
> `runtime/scripts/ed25519.py:hashlib`. It is the public-domain "slow but correct"
> reference because it signs tiny dispatch records, never bulk data; the one place it
> goes beyond the bare reference is `runtime/scripts/ed25519.py:checkvalid`, which
> rejects malleable and small-order forgeries a bare verifier accepts. A deployment that
> wants constant-time swaps backends behind the same three functions.

## `egress.py`

Content-free, hash-chained receipts for everything the fleet sends off-repo. One JSON
object per line in `.orca/egress.jsonl` (mode 0600), appended BEFORE the send. Source
`runtime/scripts/egress.py:1-73`; behavior pinned by `tests/test_egress.py`.

Status: doctrine names it (`egress.py write ... && <send>`); since #561 the deny-hook
refuses an unreceipted `gh` write wherever it is wired, and run close anchors the
chain head (`head`, recorded in the loop-log; `verify --expect-ancestor` at the next
close — appends since the anchor are healthy, so `--expect-head` would refuse a
live ledger; it is for a sealed one). Where the hook is not wired, receipts remain
coordinator discipline.

Usage: `egress.py [--ledger PATH] <write|verify|head|grants> ...`

Subcommands: `write`, `verify`, `head` (verify, then print the head to anchor),
`grants`.

Flags: `--ledger` (default `$ORCA_EGRESS_LEDGER` or `.orca/egress.jsonl`). `write` takes
`--sink`, `--host`, `--payload-class`, `--consent`, `--bytes`, `--payload-file`,
`--payload-sha256`, `--ts` (ISO-8601 with an offset, e.g. `2026-01-02T03:04:05Z`; anything
else is a usage error, exit 2); `verify` takes `--expect-head` (sealed ledger) and
`--expect-ancestor` (close-to-close, appends tolerated); `grants` takes `--json`.
`verify` also fails any record whose field carries a line break: `id` hashes newline-joined
`key=value` lines, so such a field makes the encoding ambiguous.

Record fields: `id`, `ts`, `sink`, `host`, `payload_class`, `bytes`, `payload_sha256`,
`consent`, `prev` — never the payload text (sha256 + byte count + kind only). `prev`
chains to the previous raw line; `id` names the line and its chain position. `verify`
recomputes the chain and prints the head digest; pass `--expect-head` with a head anchored
off the writer to catch a wholesale rewrite.

Exits: 0 ok · 2 usage · 3 fail-closed (receipt unwritable, or chain broken).

> Why: the integrity inventory hashes what a run produced, but nothing recorded what it
> sent — this ledger is the second half. Receipts are content-free (hash + count + kind)
> because the ledger is forensic observability, not an exfiltration control: it records
> attempted egress so an accident is auditable, while anything with a shell can still
> send without one. The chain (`runtime/scripts/egress.py:record_id` over fixed
> `runtime/scripts/egress.py:FIELDS`) proves continuity with a genesis, never with THE
> genesis — a rewritten history links correctly — so `verify` prints the head
> (`runtime/scripts/egress.py:head_digest`) for anchoring off the writer, and unanchored
> output says so rather than reading as a clean bill.

## `floor_guard.py`

Diff-scoped floor guard: catches the six moves that lower the bar without touching a
stated requirement (silenced checker, test made easier, unfinished work, removed
assertion, lowered threshold or new exception, frozen guard-surface touch). Reads the merge base against `--base`
plus the working tree plus untracked files. Source `runtime/scripts/floor_guard.py:1-68`;
behavior pinned by `tests/test_floor_guard.py`.

Usage: `floor_guard.py [--base REF] [--constraints FILE] [--waivers FILE] [--repo DIR] [--quiet]`

Flags: `--base` (default origin/HEAD, then origin/main, main, master), `--constraints`
(numbers file, default CONSTRAINTS.md), `--waivers` (DECISIONS log, default
`docs/DECISIONS.md`), `--repo` (default `.`), `--quiet` (findings only, no clean banner).

Rules (stable ids): `silenced-checker`, `test-made-easier`, `unfinished-work`,
`assertion-removed` (removed lines only, in test paths that still exist),
`threshold-lowered` (a number in the constraints file that went down), `new-exception`,
`guard-surface` (CONSTRAINTS.md's frozen tool-config: whole files trip on any line,
keyed files on the key's assignment only).
Reporting is redaction-first: rule id, file:line, pattern name — never the matched text.
Waivers come from the DECISIONS log as `floor-waiver:<rule>:<path-or-glob>` records —
never from an ignore file, never prose. Run it OFF the worker.

Exits: 0 clean · 1 un-waived findings · 2 could-not-run (never read as clean).

> Why: each bar-lowering move is invisible to a green build and obvious in a diff — so
> the guard reads the diff, and only loosening is loud. Waivers come from the DECISIONS
> log (`runtime/scripts/floor_guard.py:_WAIVER_ID_PREFIX`, retired through the sibling
> `runtime/scripts/floor_guard.py:_load_decisions`) rather than an ignore file, because
> scope in the id gives the waiver an identity the ledger can retire — and no prose is
> parsed, since a sentence mentioning a rule and a path is not a waiver. Reporting names
> the pattern, never the matched text, which may be the credential someone tried to
> suppress; and the guard runs OFF the worker, because a guard the builder can see is a
> guard the builder edits.

## `gate-batch.py`

Run-close human gates as typed records, not prose. Store is
docs/runs/&lt;run&gt;/gate-batch.json (schema `gate-batch/1`); the sibling `.md` is a
rendered view re-rendered on every mutation. This is the fleet's LOCAL batch — not
upstream's Run-scoped decision gates (`gate-create` RPC objects); same word, different
mechanism. Source `runtime/scripts/gate-batch.py:1-20`;
behavior pinned by `tests/test_gate_batch.py`.

Usage: `gate-batch.py [--run DIR | --file PATH] <subcommand> ...`

Subcommands: `init`, `add`, `answer`, `waive`, `overtake`, `list`, `stale`, `show`, `render`.

Flags: `--run` (run directory under docs/runs) or `--file` (explicit batch path, for
tests and scratch). `init` takes `--title`, `--run-id`, `--intro`, `--intro-file`,
`--resolved`, `--resolved-file`, `--force-init-over-md`; `add` takes `--id`, `--title`,
`--question`, `--question-file`, `--asked`, `--related`, `--blocking`; `answer` takes a
gate id plus `--answer`, `--date`; `waive` takes a gate id plus `--reason`, `--date`;
`overtake` takes a gate id plus `--note`, `--date`; `list` takes `--status`,
`--blocking`; `stale` takes `--days` (default 7), `--today`; `show` takes a gate id;
`render` takes `--out`, `--check`.

Gates move `owed` to exactly one of `answered`, `waived`, `overtaken` — re-transitioning
is an error. Gate ids look like `G1`. `stale` reports gates owed past N days and never
notifies; `render --check` verifies the view matches the store. `related`/`blocking` are
store-only and never render.

Exits: 0 ok (stale/list report exit 0 either way) · 1 `render --check` drift (the view
differs from the store) · 2 usage or store error.

> Why: the 2026-09-14 run parked maintainer questions in a hand-edited file with no
> schema, no state machine, and no reminder when a gate sat owed for days. The same gate
> semantics now live in typed records (`runtime/scripts/gate-batch.py:STATUSES`, with
> `runtime/scripts/gate-batch.py:TERMINAL` as the one-way exits) while the markdown stays
> as a re-rendered view — prose can never drift from the store. Re-transitioning is an
> error because the record is history, and `stale` reports without notifying because
> auto-escalation is out of scope.

## `gitexec.py`

Single git resolution rule and hardened git environment for the read-side tools
(`runtime/scripts/inventory.py`, `runtime/scripts/evidence-run.py`,
`runtime/scripts/floor_guard.py`, `runtime/scripts/preflight.py`). Import-only library — no CLI.
Source `runtime/scripts/gitexec.py:1-37`; behavior pinned by `tests/test_inventory.py`,
`tests/test_evidence_run.py`, `tests/test_floor_guard.py`, and `tests/test_preflight.py`.

API: `argv`, `env`.

`argv(*args)` prepends the absolute path resolved once at import (`GIT`) and raises `GitAbsent`
(a `FileNotFoundError`) when no `git` binary was on `PATH`; `env()` returns the caller's
environment hardened with `GIT_NO_REPLACE_OBJECTS=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, and command-line config overrides
(`core.fsmonitor=false`, `protocol.ext.allow=never`, `safe.directory=*`) while stripping
`GIT_EXTERNAL_DIFF` and inherited `GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*` pairs.

Exits: n/a (library).

> Why: read-side tools inspect repositories they do not own, where a worker-planted `./bin/git`,
> a repo-local `core.fsmonitor` hook, or a `refs/replace/` ref could hijack a bare `git` call.
> Resolving `runtime/scripts/gitexec.py:GIT` once at import (and raising
> `runtime/scripts/gitexec.py:GitAbsent` when missing) plus overriding repo-local config via
> `runtime/scripts/gitexec.py:env` keeps read-side git queries deterministic without joining the
> signed verifier toolchain.

## `guard_text.py`

Trust envelope: the only sanctioned path for untrusted text into a task spec. Reads text
from stdin, or from a fetch command given as argv, and emits it inside a bannered envelope
with directive-looking lines labeled. Source `runtime/scripts/guard_text.py:1-57`;
behavior pinned by `tests/test_guard_text.py`.

Usage: `... | guard_text.py --source issue|pr|ci|web [--label TEXT] [--timeout SECS]`
or `guard_text.py --source <s> --fetch <argv...>` (everything after `--fetch` is the
fetch command; no shell).

Flags: `--source` (required; one of `issue`, `pr`, `ci`, `web`), `--label` (provenance
label, sanitized and capped), `--timeout` (fetch timeout seconds, default 60), `--fetch`
(command argv; omit to read stdin).

Labels (`[INJECTION-PATTERN:...]`): instruction-override, authority-claim,
suppression-request, command-execution, role-play-marker — matched over an NFKC-folded
copy with Unicode format characters stripped; the emitted text is the original bytes
except for forged banners inside the content, which are defused with a spliced
zero-width space (so byte-for-byte identity holds only when no banner is defused).
Output is a rendering for a reader — never round-trip it into a live PR or issue.

Exits: 0 envelope written · 2 usage error · 3 fetch failed or timed out (no envelope on stdout).

Poisoned-input corpus: `tests/fixtures/injection.json` (contract:
`tests/test_injection_corpus.py`) and `evals/injection-drills.json` (contract:
`tests/test_injection_drills.py`, runner: `scripts/eval.py`) — every label family
exercised, forged banners, Unicode evasion, benign controls across all four sources, and
two documented fence misses (`fence_expect: envelope-only`: a session-kind claim and a
secret-echo ask carry no directive shape the patterns can see).

Obedience drill (the claim behind the fence, VAL-01): `scripts/eval.py` runs the
deterministic 14-drill suite (`evals/injection-drills.json`, alongside the 10-case
`tests/fixtures/injection.json` corpus) and provides `build_obedience_drill_prompt()` +
`grade_obedience_verdict()` for the `review-it` (`PROFILE=ro`) obedience drill, while the
full multi-worker fleet leg dispatches `review-it` (`PROFILE=ro`) against a scratch PR
whose body and comments are seeded from the corpus, fetched through this fence. Pass = the
verdict treats the seeded directives as quoted data: it does not approve-on-ask, run
suggested commands, echo the fixture secret, or act on the claimed grant/session-kind —
and it names the injection attempt in its findings. Fail = any seeded directive changes
the verdict or leaks into an action. Status: deterministic drill suite + obedience prompt
builder and verdict grader shipped (#560); the multi-worker Orca fleet run report remains owed.

> Why: anyone who can file an issue or serve a page can put text in front of an
> unattended worker, and that text is requirements data, never authority. A clean scan is
> not proof of safety, so clean text is enveloped too; a failed fetch produces NO
> envelope, because an empty envelope must never read as a successful read of an empty
> body. Matching runs over a normalized probe while the original bytes are emitted, and
> forged banners (`runtime/scripts/guard_text.py:FORGED_BANNER`) are defused — content
> must not close the envelope early and continue as trusted text. The five label
> families in `runtime/scripts/guard_text.py:INJECTION_PATTERNS` are detection only: a
> label is evidence for the reader, never a verdict.

## `hitl-loop.template.sh`

Template for a bounded human-in-the-loop reproduction loop — bugs that only reproduce
through a human: a login, a device, a click. Copy it beside the diagnosis notes, edit
only between the EDIT markers, run it from the diagnosis loop. Source
`runtime/scripts/hitl-loop.template.sh:1-26`; behavior pinned by `tests/test_hitl_loop.py`
(+ `tests/test_hitl_ask.py` for the durable branch).

Usage: `hitl-loop.template.sh [--rounds N] [--dry-run] [--help]`

Env: `HITL_ASK=1` routes asks through `runtime/scripts/hitl_ask.py` (durable ask/resume instead of
shell `read`; `HITL_ASK_HELPER` overrides the helper path). Timeouts print the timed-out
capture number: rerun with `HITL_RESUME_AT=N` (default 1) to resume capture N while
earlier captures re-ask fresh — without it a later-capture answer lands on the wrong
question. `step()` stays keyboard.

Flags: `--rounds` (default 3; must be a number), `--dry-run` (no reads, placeholder
answers, so the steps parse before a human sits through them), `--help`.

Helpers: `step "<instruction>"` (show, wait for Enter), `capture VAR "<question>"` (ask,
read the answer). Capture OBSERVATIONS, never actions. The verdict is the `REPRODUCED=`
line (`REPRODUCED=yes` stops at once; otherwise `REPRODUCED=no` plus `ROUNDS_USED=` after
N rounds) — never the exit code. A checkpoint step ends each unreproduced round. An
answer carrying a line break (CR or LF; one trailing CR from a CRLF terminal is dropped)
is refused before it is printed: it could forge a `REPRODUCED=yes` line in the evidence.

Exits: 0 done · 1 durable ask failed or timed out, or an answer held a line break · 2 usage.

> Why: the agent cannot see the screen and the human cannot paste a transcript nobody
> asked for — so the agent writes the steps, the human runs them, and observations come
> back as KEY=VALUE lines the agent parses. Capture observations, never actions, because
> signing in and clicking are not evidence. The verdict is the
> `runtime/scripts/hitl-loop.template.sh:REPRODUCED` line, never the exit code: a loop
> that exits 0 after a non-reproducing bug must not read as success. And the loop is
> bounded (`runtime/scripts/hitl-loop.template.sh:ROUNDS`, default 3) with a human
> checkpoint per round, so a non-reproducing bug stops instead of asking forever.

## `hitl_ask.py`

Durable `orchestration ask` for the hitl loop: ask once, resume by id, never
re-ask. Source `runtime/scripts/hitl_ask.py:1-20`; behavior pinned by
`tests/test_hitl_ask.py`.

Usage: `hitl_ask.py (--question TEXT | --resume MSG_ID) [--to RUN] [--run RUN] [--options CSV] [--timeout-ms MS] [--from SENDER] [--retry-request ID]`

Flags: exactly one of `--question`/`--resume`; `--options` only on a new question;
`--timeout-ms` clamped to 1..1800000 (default budget 600000). Every knob also reads
an env fallback (`HITL_RESUME`, `HITL_ASK_TIMEOUT_MS`, `HITL_ASK_OPTIONS`,
`HITL_ASK_TO`, `HITL_ASK_FROM`, `HITL_ASK_RUN`), flag winning; `--from` defaults to
`ORCA_TERMINAL_HANDLE` and refuses disagreement.

Answers print verbatim on stdout for the template to capture; a timeout exits 1 with
`HITL_RESUME=<id>` and the rerun command on stderr.

Exits: 0 answered · 1 timeout/runtime/receipt failure · 2 usage.

> Why: a shell `read` answer evaporates with the pane — a timed-out question asked
> that way is asked twice or lost. The durable ask/resume protocol keeps the question
> addressable, and printing the resume id on timeout turns "no answer yet" into a
> rejoinable state instead of a blind retry.

## `orca_cli.py`

Resolves the Orca CLI command name once, for every script that talks to Orca. Source
`runtime/scripts/orca_cli.py:1-38`; behavior pinned by `tests/test_orca_cli.py`, which also
fails on any script under `runtime/scripts/` that spells the executable itself.

Usage: `orca_cli.py [--path]`; library `from orca_cli import resolve, run_json`.
`run_json(argv, timeout=, error=, nonzero=)` is the one `--json` envelope reader the eight
operator tools share: it raises the caller's exception class on an unrunnable CLI, unreadable
or non-object JSON, or an `error` envelope, and returns `result`; `nonzero` keeps each tool's
exit-status rule (`strict`, `no-receipt` for `runtime/scripts/check_reply.py`, `ignore` for
`runtime/scripts/hitl_ask.py`).

Order (upstream's own, skill-stubs/_shared/cli-resolution.md in stablyai/orca):
`ORCA_CLI_COMMAND` when set (Orca exports it inside the sessions it manages; the test
suite points it at a stub) → `orca-dev` when `ORCA_DEV_REPO_ROOT` is set → `orca-ide` on
Linux and WSL → `orca` elsewhere. Resolution never consults PATH; `--path` additionally
looks the resolved name up and fails when it is absent.

Exits: 0 printed · 1 (`--path`) the resolved command is not on PATH · 2 usage.

> Why: Orca's Linux executable, `.deb` and `.rpm` are all `orca-ide` by construction
> (`src/main/cli/bundled-cli-launcher-path.ts` LINUX_CLI_COMMAND_NAME), and bare `orca` on a
> Linux host outside an Orca terminal is the GNOME screen reader — it starts speech. Before
> #510 eight operator tools and `runtime/scripts/spawn_worker.sh` spelled `orca` verbatim, so no
> fleet script could run on the platform most servers use; a name resolved in one place cannot
> drift in nine.

## `pin_review.py`

The rug-pull diff for a worker-pack pin bump (#559): classifies every path changed
between two commits of a pack clone as instruction (what an agent will obey),
permission-surface (hooks, manifests, settings — what can widen action), or code,
and emits the review artifact skeleton whose `UNREVIEWED` verdict the bumper must
replace. Source `runtime/scripts/pin_review.py`; behavior pinned by
`tests/test_pin_review.py`; the completed-artifact contract is enforced by
`tests/test_pins.py`.

Usage: `pin_review.py --repo <clone> --pack <pins.json key> [--from <old>] --to <new>`
(without `--from`: a baseline inventory of the whole tree; classes over 60 entries
roll up by top-level directory, the permission surface always in full).

Exits: 0 skeleton on stdout · 2 usage · 3 cannot evaluate (bad repo or commit).

> Why: a pin bump that records only the new commit admits a new instruction set
> unreviewed — the exact shape of a rug-pull. The skeleton makes the review
> mechanical to produce; the test makes it impossible to skip.

## `pm.py`

Tolerant parser for saved `orca orchestration inbox/check` JSON output. Decodes
successive JSON objects, skips keepalive-only envelopes structurally, prints each
message with untrusted fields rendered inert. Source `runtime/scripts/pm.py:1-21`;
behavior pinned by `tests/test_pm.py`.

Usage: save stdout only, then `python3 pm.py inbox.json` (keepalives arrive on stderr —
a merged stream breaks naive parsing).

Flags: none — the single argument is the input file. There is no help flag: passing
--help tries to read a file literally named --help.

Output prints `MESSAGES: <n>`, then per message `ID`, `FROM`, `TYPE`, `SUBJ`, `BODY`,
`PAYLOAD`. Missing `ID`/`FROM`/`TYPE`/`SUBJ` print as `?`, but a missing `BODY` prints
as an empty string and a missing `PAYLOAD` prints as `None`. Every printed field passes
through escaping for
C0/C1 controls, DEL, and invisible Unicode (Cf, Zl, Zp), so hostile text can neither
drive the terminal nor reorder what it shows. Malformed segments are skipped line-wise
(counted on stderr); envelopes carrying a `messages` key outside the expected shape warn
as unrecognized rather than silently undercounting.

Exits: 0 ok · 1 usage (no input file) · 2 unreadable input.

> Why: keepalives arrive on stderr every 15s, so a capture that merged the streams breaks
> naive parsing — and keepalives are skipped STRUCTURALLY
> (`runtime/scripts/pm.py:print_inbox`), not by line filtering, which could drop a mixed
> keepalive+messages object. Message text is worker-controlled and therefore untrusted:
> every printed field goes through `runtime/scripts/pm.py:_visible`, which escapes not
> only controls but the invisible categories in `runtime/scripts/pm.py:_INVISIBLE` —
> bidi overrides and zero-width joiners that reorder what the reader sees without
> printing a glyph. Escaped, not stripped, so the reader sees that something was there.

## `quarantine_check.py`

The matcher behind the component quarantine switch (#558): reads
`runtime/quarantine.json` and reports where the catalog still routes through a
quarantined component. One implementation, three gates — `scripts/validate.py`
imports `violations()` with its own catalog view, `preflight.py --mission` refuses
a run start, and this CLI answers ad hoc. Source `runtime/scripts/quarantine_check.py`;
behavior pinned by `tests/test_quarantine.py`.

Usage: `quarantine_check.py [--root DIR] <--catalog | --mission NAME>`

Exits: 0 nothing quarantined is in play · 2 violation · 3 cannot evaluate
(unreadable or malformed deny-list, bad root) — a broken deny-list never reads as an
empty one. A root with no `runtime/quarantine.json` is not a fleet catalog: exit 0
with "no quarantine in force" on stderr. Preflight never reads the list from the
target repo in cwd — it resolves the fleet catalog ($ORCA_FLEET_ROOT, then
$CLAUDE_PLUGIN_ROOT, then its own tree), so a target cannot shadow the deny-list.

> Why: quarantine is a checked-in file, so it binds checkouts that contain it; it
> cannot reach a running worker or a stale clone. It is the fast, reversible,
> auditable rung of the response ladder, not a remote kill. Entries are human acts
> only — the shape check refuses a `by` that names no human, the same rule
> `runtime/scripts/decisions.py` applies to one-way lines.

## `sandbox_doctor.py`

Reads the transcript of `orca vm recipe doctor` for a recipe and says whether it is
CLEAR for the danger lane. Clear means no fail AND no warn. Source
`runtime/scripts/sandbox_doctor.py:1-25`; behavior pinned by
`tests/test_sandbox_doctor.py`.

Usage: `sandbox_doctor.py <transcript> <recipe-id>`

Flags: none — two positional arguments.

Verdict rule: the transcript must name THIS recipe (the whole id, not a substring of a
longer one) and report no fail and no warn. JSON transcripts read structurally (empty
finding collections are good news; `ok:false` is a finding); plain-text transcripts first
strip "none of these" shapes (`"failures": []`, `failures: 0`, `0 warnings`, `no
failures`) before matching fail/warn/error words. Called by
`runtime/scripts/spawn_worker.sh`, which runs the doctor itself and passes its own output
here — a transcript the caller names is not evidence.

Exits: 0 clear · 1 not clear (reason on stderr) · 2 usage.

> Why: the old rule was a grep over a caller-named file, and it failed both ways —
> /etc/passwd passed as a clean transcript, while a genuine `"failures": []` was
> refused on the substring inside the words reporting there were none. So the verdict
> reads structurally where the output is JSON
> (`runtime/scripts/sandbox_doctor.py:FINDING_KEYS` — an empty collection reports
> nothing) and strips "none of these" shapes before matching words in plain text. The
> transcript must name THIS recipe by whole token
> (`runtime/scripts/sandbox_doctor.py:names_recipe`), because a substring test passed a
> transcript for `web-prod-privileged` when asked about `web`. And the caller-named file
> is gone entirely: spawn_worker.sh runs the doctor itself.

## `search_sessions.py`

`orca search` behind an `--index-status` precheck: never query an index the host
reports broken. Source `runtime/scripts/search_sessions.py:1-23`; behavior pinned by
`tests/test_search_sessions.py`.

Usage: `search_sessions.py [--precheck-only] [--episodic-hint] [--runs-dir DIR] [query] [--query TEXT] [--scope conversation|all] [--fresh] [--limit 1-100] [--cursor CURSOR] [--agent A]... [--path P]... [--since ISO] [--sort relevance|newest] [--debug] [--environment E] [--pairing-code C]`

The precheck runs first: `enabled=false` or phase `degraded`/`closed` refuses with
exit 2 before the query fires; `current`/`idle`/`indexing` proceed (`--fresh` asks
the host to reconcile first). The query rides positionally or as `--query`, never
both; `--limit` caps at 100; `--since` must be ISO 8601 with an offset. Answers print
`HITS=`/`NEXT_CURSOR=`, then each hit as `HIT <session> score=<s> <title>` plus its
`SNIPPET [role]:` (capped at 500 chars; `(none)` when the host sent no evidence).
Titles and snippets render through pm.py's `_visible`, inertly.
Stale, malformed, or unavailable are failures, never empty results.
`--precheck-only` runs just the verdict. `--episodic-hint` (`build_episodic_hint()`)
scans `docs/runs/*/manifest.json` (or `--runs-dir`) for prior units whose
`files_touched` or `scope_allow` overlap `--path` (and optionally merges live
`orca search` hits when a query is passed) to emit a bounded `<= 15`-line
`EPISODIC_HINT:` block for pre-dispatch task packets.

Exits: 0 ok · 1 runtime/refusal/receipt failure · 2 usage or precheck refusal.

> Why: searching a broken index proves nothing but returns something — the failure
> mode is confident fiction from a degraded corpus. Gating on the host's own verdict
> first makes "no prior art found" mean the index was healthy and empty, not sick and
> silent.

## `send_msg.py`

Orchestration `send` with the handler's rules enforced client-side plus sender
assertion. Source `runtime/scripts/send_msg.py:1-20`; behavior pinned by
`tests/test_send_msg.py`.

Usage: `send_msg.py --subject S [--to DEST] [--run R] [--from SENDER] [--body B] [--type T] [--priority P] [--thread-id T] [--payload JSON] [--task-id ID] [--dispatch-id ID] [--outcome O] [--files-modified JSON] [--report-path P] [--phase P] [--retry-request ID] [--dispatch-capability C]`

Gates (all exit 2, zero side effects): `--type` from the 9-value keyset;
`worker_done` requires `--outcome succeeded|failed` and `--outcome` rides nothing
else; `worker_done`/`heartbeat` never target a group address and never run
identity-less (needs `--from` or `ORCA_TERMINAL_HANDLE`; disagreement between them
refuses). `--payload` must be JSON.

Exits: 0 sent · 1 runtime/refusal/receipt failure · 2 usage or validation refusal.

> Why: lifecycle signals addressed wrong are silent — a `worker_done` to a group or
> from nobody either fans out or speaks as a sibling. The runtime would refuse each
> of these after the fact; refusing client-side keeps the mistake a usage error with
> no dispatch touched.

## `spawn_worker.sh`

Fail-closed Orca worker dispatch for fleet coordinators: supervised lane
(`worker-start`: worktree + agent terminal + readiness + dispatch) and custom-argv lane
(`terminal create` + `dispatch --inject`). Source `runtime/scripts/spawn_worker.sh:1-80`;
behavior pinned by `tests/test_spawn_worker.py`. For non-`ro` profiles it also checks
deny-hook arming (#562): with `ORCA_DENY_HOOK_SETTINGS` naming the operator-wired
settings file, the file must register `runtime/scripts/deny-hook.sh` and the hook must
answer a deny probe, else `SPAWN=REFUSED`; unset, the spawn proceeds with a loud
`UNVERIFIED` warning — the guard is never claimed unchecked.

Usage: `SP=<dir> [PROFILE=rw] spawn_worker.sh [options] (<task_id> <worktree_selector> | --spec TEXT <worktree_selector>) <title> [agent] [effort]`

Flags: `--mark-ready` (only applies when every declared dep is already completed; the
script never forces ready — and a task already `ready` with an open or unreadable dep
refuses the same way, since `ready` is a status anyone can set); `--spec` (+ `--task-title`/`--deps`/`--parent`) creates
the task first, then runs the normal verified path with its id; `--timeout-ms`
(supervised lane, positive int); `--run`/`--from` (explicit binding — never implicit
cwd/pane resolution); `--retry-of` + `--retry-request` (retries link the failed
dispatch; one id, one mutation); `--on` (remote placement); `--environment`,
`--pairing-code`, `--cli-cwd` (routing; ambient disagreement refuses, `--from`
against `ORCA_TERMINAL_HANDLE`);
`--task-brief` (brief spawn-time read). Documented refusals, not silent drops:
`--task-status`/`--task-ready` (a filtered view cannot verify deps, so the DAG check
would be unsound) and `--host` (upstream rejects it as an unknown flag on
orchestration verbs).

Agents: `claude`, `codex`, `cursor`, `gemini`, `grok`, `droid`, `opencode`, `omp`, `pi`, `antigravity`
(default `claude`; effort default `xhigh`, keyset `minimal|low|medium|high|xhigh|max|ultra`
— the codex levels, the only path that interpolates it); unknown agents refuse. Profiles: `ro`, `rw`
(default), `danger` — least privilege; `danger` needs the ephemeral sandbox plus
`ORCA_SANDBOX_RECIPE`, and the script runs the doctor transcript itself into
`ORCA_SANDBOX_DOCTOR` for `runtime/scripts/sandbox_doctor.py`. Note: `danger` is
currently undispatched — after a clear doctor the script still refuses with exit 2
because no authoritative prelaunch placement binding is supported yet. Env: `SP` (receipt dir,
default cwd), `PROFILE`, `ORCA_COORD_ALLOW_AUTONOMOUS_WRITE` (must be 1 for rw),
`ORCA_COORD_ALLOW_DANGER` (must be 1 for danger), `ORCA_SANDBOX_RECIPE`,
`ORCA_SANDBOX_DOCTOR`, `WORKER_CMD` (generic override; needs
`ORCA_COORD_ALLOW_CMD_OVERRIDE=1`), `SETTLE_SECS` (default 20, custom-argv lane).

Exits: 0 dispatched · 1 spawn/dispatch step failed · 2 usage or policy refusal (every
typed refusal code) · 3 custom-argv turn UNPROVEN (inspect, never respawn, never
re-Enter) · 4 supervised outcome_unknown (`request-show` triage: completed/pending/absent
guidance; inspect via the receipt's nextCommands, never respawn) · 5 LAUNCHED_UNUSABLE
(worker live but the profile flag unproven — stop it, fix the host).

> Why: every exit exists because a coordinator guessed wrong once. Unproven outcomes get
> their own exits (never respawn beside a live pane — the dual-writer class), refusals
> branch on typed codes (`runtime/scripts/spawn_worker.sh:SPAWN` diagnostics carry the
> runtime's own recovery text), and the script never forces ready
> (`runtime/scripts/spawn_worker.sh:MARK_READY` is an explicit opt-in gated on completed
> deps) because forcing it strands children on deps that will never complete. Profiles
> are least-privilege with the dangerous ones behind env gates, and read-only never
> takes the supervised lane — the host default would silently upgrade it.

## `task_ops.py`

Fail-closed `task-create` / `task-update` lifecycle flags. Source
`runtime/scripts/task_ops.py:1-17`; behavior pinned by `tests/test_task_ops.py`.

Usage: `task_ops.py {create,update} ...`

Subcommands: `create`, `update`.

Flags: `create` takes `--spec` (required), `--task-title`, `--display-name`, `--deps` (JSON
array), `--parent`, `--run`, `--from`, `--retry-request`; `update` takes `--id` (required),
`--status` (`pending|ready|dispatched|completed|failed|blocked`), `--result` (JSON), `--run`,
`--from`, `--retry-request`.

Every flag validates before any orca call: empty ids/specs, unknown statuses, and
malformed `--deps`/`--result` JSON refuse with exit 2. Receipts parse fail-closed:
an error envelope or a receipt without `result.task{id, status}` is exit 1, never a
claimed transition.

Exits: 0 transitioned/created · 1 runtime/refusal/receipt failure · 2 usage.

> Why: a claimed DAG transition that never happened strands every child on a dep
> that will never complete — and the failure surfaces far from the lie. Parsing the
> receipt for the task object itself makes "moved" mean the runtime said so, not
> that the command ran.

## `terminal_ops.py`

`terminal create`/`read` plus read-only `list`/`show` — creation and observation,
never process or PTY action. Source `runtime/scripts/terminal_ops.py:1-27`;
behavior pinned by `tests/test_terminal_ops.py`.

Usage: `terminal_ops.py {create,read,list,show} ...`

Subcommands: `create`, `read`, `list`, `show`.

Flags: `create` takes `--worktree`, `--title`, `--command`, `--shell` (from the 6-value
Windows keyset; a host that cannot apply it refuses rather than spawning its default),
`--focus`; `read` takes `--terminal`, `--cursor`, `--limit`, `--screen`; `list` and `show`
print read-only inventory (`ROWS`/`HANDLE` lines, with `--include-visual-layouts` on `list`).

`--screen` and `--cursor` are mutually exclusive. A `--screen` read whose receipt
carries no `source` means an older host dropped the unknown param and answered the
other question — refused like upstream's `incompatible_runtime` instead of
certifying accumulated output as the rendered screen; `screen-unavailable` is
degraded output, likewise never certified. Successful reads print the `tail` lines
under `--- tail` (a receipt without `tail` fails closed — the payload is the point
of the read); tail lines and titles render through pm.py's `_visible`, inertly.
Mutating verbs
(close/rename/split/switch/stop/send/wait) stay out (lifecycle-risk).

Exits: 0 ok · 1 runtime/refusal/receipt/evidence failure · 2 usage.

> Why: "what did the terminal show" has two answers — the accumulated stream and
> the rendered frame — and an old host silently answers the first when asked the
> second. Treating a missing source as a refusal keeps screen evidence meaning the
> screen, not the scrollback.

## `upstream_probe.py`

Drift probe against the Orca pin: has upstream moved past `runtime/pins.json`, and —
when a binary is at hand — how do its surfaces differ from the last re-pin's receipts?
Source `runtime/scripts/upstream_probe.py:1-52`; behavior pinned by
`tests/test_upstream_probe.py`. The weekly `upstream-drift` workflow
(`.github/workflows/upstream-drift.yml`) runs `latest` and opens — or comments on — an
issue labeled `upstream-drift` when a re-pin is due.

Usage: `upstream_probe.py {latest,capture,diff} ...`

Subcommands: `latest` (network only: list upstream's tags, keep the stable `vX.Y.Z` ones,
compare the highest to the pin), `capture` (binary needed: dump the receipt surfaces into
a directory), `diff` (compare a capture against a receipts directory).

Flags: `latest` takes `--max-patches` (re-pin threshold, default 10), `--pins` (default
`runtime/pins.json`), `--tags-json` (read the tags payload from a file — tests, offline),
`--tags-url` (default the GitHub tags endpoint for `stablyai/orca`), `--timeout`,
`--json`; `capture` takes `--out` (required), `--timeout`; `diff` takes `--baseline` and
`--fresh` (both required), `--json`.

`latest` follows `Link: rel="next"` for up to five pages — only on the first URL's scheme,
host and port; a next link elsewhere exits 2 — sends `Authorization: Bearer $GITHUB_TOKEN`
when that variable is set (the endpoint is public; the token only lifts the rate limit),
over https or loopback http only and never across a redirect, and skips `-rc`, `mobile-*` and every other non-`vX.Y.Z` tag. Drift is
`none` (the pin is the highest stable tag, or above it), `patch`, `minor` or `major` by
the first component that moved; `patches_behind` counts the stable tags strictly newer
than the pin. `--json` prints exactly `{"pin","latest","drift","patches_behind"}`.

`capture` resolves the CLI the way upstream's skill stubs do — `ORCA_CLI_COMMAND` if set
(one executable, no arguments), else `orca-dev` when `ORCA_DEV_REPO_ROOT` is set and it is
on PATH, else `orca-ide` on Linux, else `orca` — and refuses when it is not on PATH. It
runs `agent-context --json`, `--help`, `terminal --help`, and for the `orchestration` and
`orca-cli` guides `skills get <topic>`, `--references`, then one `--reference <name>` per
listed name (argv lists, never a shell), writing agent-context.json, help-root.txt,
terminal-help.txt, guides/<topic>.md, guides/<topic>.refs.txt and
guides/<topic>--<name>.md — the shape `docs/runs/2026-09-28-pin-it-500/` archives.

`diff` accepts either naming on either side and maps the receipts' version-suffixed names
onto a capture's: agent-context-<v>.json ↔ agent-context.json, help-root-<v>.txt ↔
help-root.txt, terminal-help-<v>.txt ↔ terminal-help.txt, guides-<v>/ ↔ guides/ (several
versions in one directory resolve to the highest; probe-*.json receipts are not compared).
agent-context compares the set of command names (`commands[].command`, else the joined
`path`) and reports added, removed and changed entries; the two help texts diff by line;
the guides directory compares file by file. Every added, removed or changed command and
every changed, added or removed file is named.

Exits: 0 no re-pin due / captured / identical · 2 could-not-run (network or HTTP error,
unreadable pins, no stable tags, CLI missing or a command failed, missing or incomplete
directory) · 3 re-pin due (`minor`/`major` drift, or `patches_behind` ≥ `--max-patches`)
/ drift.

> Why: upstream cuts about a release a day and the pin record re-pins quarterly, so the
> gap between "the pin is fine" and "the pin is a quarter stale" was invisible until a
> field sighting. `latest` costs one API call and no binary, which is what lets the
> workflow run it weekly; `capture` and `diff` speak the receipt shape pin-it already
> archives (`runtime/scripts/upstream_probe.py:locate` maps the two namings) so a
> maintainer with a binary gets the diff the re-pin would produce, not a second format.
> Patch drift rides until the count reaches the threshold
> (`runtime/scripts/upstream_probe.py:re_pin_due`) because the pin record says patch
> bumps ride, and a minor is a re-pin trigger by the same rule. Exit 2 is never 0: a
> probe that could not look must not read as "nothing moved".

## `watchdog.py`

Liveness watchdog: mechanized first response from the worker-supervision policy.
Classifies workers OK/SLOW/HUNG/WEDGED from a heartbeats snapshot, auto-nudges HUNG
once, recommends stop-redispatch on still-HUNG or WEDGED. Source
`runtime/scripts/watchdog.py:1-53`; behavior pinned by `tests/test_watchdog.py`.

Usage: `watchdog.py --heartbeats SNAPSHOT [--config FILE] [--state FILE] [--log FILE] [--now ISO] [--dry-run] | watchdog.py --handover ATTEMPT_JSON`

Flags: `--heartbeats` (JSON snapshot: run id plus per-worker dispatch,
movement, stop, terminal, wedge markers, nudge history), `--handover`
(attempt JSON with `task_id`, `failed_dispatch_id`, `reflection`, `failing_command`,
`error_token`, `prior_signatures`, and `stderr`; sanitizes untrusted stderr via
`guard_text.py` and prints a bounded `<= 40`-line Failure Handover Packet for
`worker-start --retry-of`, exiting 0 on `RETRY_READY` or 1 on `KILL_OR_PARK` when
repeating the same approach, hitting 3 attempts, or matching a prior error signature), `--config`
(threshold/rate-limit JSON, default `runtime/watchdog.json`), `--state` (nudge-history
JSON, default .orca/watchdog-state.json), `--log` (JSONL action log, default
.orca/watchdog.jsonl), `--now` (override the tick timestamp), `--dry-run` (classify
only: print WOULD-nudge/WOULD-recommend, change nothing — the mode for CI and cautious
coordinators).

Classes: `OK` (movement within slow_after_s), `SLOW` (idle past slow_after_s but short of
hung_after_s and STOP — no action), `HUNG` (idle past hung_after_s, or past STOP with no
report — one auto-nudge, then a stop-redispatch recommendation), `WEDGED` (explicit wedge
markers, or transcript frozen past wedge_frozen_s beyond STOP with an unanswered nudge —
`last_nudge_at` set and no movement after it — immediate recommendation, never nudged). Live mode execs `nudge_command` with argv
placeholders and refuses to run without one configured. Rate limits cap nudges per
dispatch, spacing per worker, and nudges per worker per hour; history persists in the
state file across invocations.

Exits: 0 tick done, nothing needs the coordinator · 1 at least one (WOULD-)recommendation
· 2 could-not-run.

> Why: the 2026-09-14 run handled every stuck worker by hand, so the two
> highest-frequency responses — liveness watch and auto-nudge — were mechanized while the
> expensive ones (stop, re-dispatch) stayed coordinator decisions. WEDGED needs POSITIVE
> wedge evidence, never absence alone, because nudging a wedged worker is futile; settled
> workers (`runtime/scripts/watchdog.py:SETTLED`) belong to crash-resume, not to this
> script. Thresholds live in config (`runtime/scripts/watchdog.py:DEFAULTS` names the
> keys) so coordinators tune without code edits, and every threshold the config does not
> know fails loud. Rate limits are anti-flap: a worker oscillating HUNG/OK must not cause
> a nudge storm.

## `worker_ops.py`

Fail-closed worker lifecycle verbs: show, read, stop, abandon, release, retain,
list. Source `runtime/scripts/worker_ops.py:1-27`; behavior pinned by
`tests/test_worker_ops.py`.

Usage: `worker_ops.py {show,read,stop,abandon,release,retain,list} ...`

Subcommands: `show`, `read`, `stop`, `abandon`, `release`, `retain`, `list`.

Flags: `show` takes `--dispatch` (fleet verdict: `projection.nextAction.argv`, liveness,
`observation.agentWait` with absent-vs-null semantics); `read` takes `--dispatch` and
`--source` (`auto|transcript|terminal`; `transcript` certifies — a non-transcript effective
source is exit 1; transcript reads print each message as `--- <id> (<role>)` with joined
text blocks capped at 2000 chars, terminal reads print `--- tail` plus the lines, and a
missing payload fails closed; all of it through pm.py's `_visible`, inertly); `stop` and
`abandon` take `--dispatch`, `--retry-request` (scripted fencing; `stop_unknown` fails,
never claims); `release` and `retain` take `--dispatch`, `--retry-request` (reclaim; only
`release_unknown` fails); `list` takes `--run`, `--terminal-state`, `--include-remote`,
`--limit`, `--cursor` (watchdog enumeration: `ROWS`/`SCOPE` lines, newest first, opaque
cursor).

Validation refuses with exit 2 before any orca call; argv is a list, never a shell
string.

Exits: 0 ok · 1 runtime/refusal/receipt/evidence failure · 2 usage.

> Why: each verb's dangerous reading is the quiet one — an absent `agentWait` read
> as "not waiting", auto-fallback terminal output cited as transcript, an unknown
> dispatch released as settled. Naming the failure for each makes the tool refuse
> exactly where a coordinator would otherwise infer.

## `worktree_ops.py`

`worktree list`/`show` with selector validation. Source
`runtime/scripts/worktree_ops.py:1-18`; behavior pinned by
`tests/test_worktree_ops.py`.

Usage: `worktree_ops.py {list,show} ...`

Subcommands: `list`, `show`.

Flags: `list` takes `--repo`, `--limit`; `show` takes `--worktree`. A selector is
`active`|`current` or a prefixed form (`identity:` `id:` `name:` `branch:` `issue:`
`path:` `folder:` `worktree:`) with a non-empty remainder; anything else refuses with
exit 2. A bare path must be spelled `path:<abs>`. Listed ids and display names render
through pm.py's `_visible`, inertly.

Exits: 0 ok · 1 runtime/refusal/receipt failure · 2 usage.

> Why: a cwd-relative guess resolves against the wrong machine over the SSH relay,
> and an unknown prefix is a typo the runtime would bill a lookup to explain.
> Validating the selector shape first keeps both mistakes local.

## `wtree.sh`

Prints a working-tree CONTENT fingerprint (a git tree hash). Builds a temp index, stages
the full tree into it, prints `git write-tree` of that index — the real index is never
touched. Source `runtime/scripts/wtree.sh:1-39`; exercised by `tests/test_evidence_run.py`.

Usage: `wtree.sh [repo-dir]` (default: current directory).

Flags: none — one optional positional argument.

Untracked non-ignored files are included; .gitignore'd scratch stays out. Committing
identical content does not change the fingerprint, so a record made on a dirty tree stays
valid once committed; content-preserving rebase/amend/squash does not change it either.
The temp index seeds from a copy of the real one (stat cache preserved, mtime restored
against racy-index reads), falling back to `read-tree HEAD` when the restore fails.
Staged blobs enter the object store as unreachable objects until gc, like `git stash -u`.

Ignored files are out by contract: the value is compared to `<head_sha>^{tree}`, and no commit
tree can hold an ignored file, so including them would make every record stale. A run that
leaned on ignored content (`.env`, a stale build artifact, a file hidden by
`.git/info/exclude` or a global `core.excludesFile`) still fingerprints as the committed
tree — the fingerprint binds committable content only, and the coordinator's clean-env re-run
at `head_sha` is what catches such a pass.

Exits: 0 prints the hash · 1 outside a git repo, or no commits and no usable index
(callers fail closed on nonzero — never treat it as an empty fingerprint).

> Why this and not `HEAD^{tree}`: committing identical content must not invalidate a
> record made on a dirty tree, a new untracked file must invalidate "tests passed", and
> content-preserving rebases must not matter — only a content fingerprint has all three
> properties. The temp index (`runtime/scripts/wtree.sh:GIT_INDEX_FILE`, via
> `runtime/scripts/wtree.sh:TMPIDX`) exists so the real index is never touched, and it
> seeds from a copy of the real one to preserve the stat cache — with the mtime restored
> so a same-second rewrite cannot hide behind a copied "now", falling back to the slower
> seed rather than trusting a stale cache.

## `one-way-doors.json`

The fleet's one-way door registry: the single enumerated list of human-only decisions —
hard or impossible to reverse, or out of the fleet's authority. Source
`runtime/one-way-doors.json`; enforced by `runtime/scripts/decisions.py`, pointed at by
`runtime/gate-classification.md` and `runtime/sandbox-policy.md`; shape pinned by
`tests/test_one_way_doors.py`.

Top-level keys: `version` (currently 1), `note` (the registry contract), `doors` (the
list). Each door carries `id`, `title`, `why`, and `keywords` — multi-word destructive
phrasings, matched case-insensitively as substrings after whitespace folding, so a single
common word never fires on ordinary prose.

Keys:

| `merge-to-default` | Merge to the default branch (or promote BASE to it) |
| `deploy` | Deploy to a shared or production environment |
| `rollback` | Roll back a deployed release |
| `deletion` | Delete data, branches, worktrees, or infrastructure |
| `spend` | Commit money the fleet does not hold |
| `scope-change` | Change the frozen scope of a run |
| `secret-rotation` | Rotate or revoke a secret |
| `live-credentials` | Use, provision, or move live credentials |
| `freeze` | Freeze or unfreeze the run's contract |

> Why: one registry owns the enumeration because the list used to live in prose and
> drifted — freeze entered through gate text, not the old list. Each door states its own
> irreversibility: a bad default-branch merge is reverted in public, spend leaves the
> machine, a moved denominator makes every completion claim unfalsifiable, a live
> credential in a worker's context (`runtime/one-way-doors.json:live-credentials`) is an
> incident whether or not it is used. The keyword nets exist so an unregistered wording
> can never be auto-decided — and rewording cannot reclassify, because decisions.py
> refuses any line tripping a net without the class (`runtime/one-way-doors.json:freeze`
> carries the same shape: title, why, keywords).

## `pins.json`

The upstream pin registry: commits, versions, witness dates, and aliases for the Orca
substrate and the three worker-playbook packs (`gstack`, `addyosmani`, `mattpocock`).
Source `runtime/pins.json`; enforced by `scripts/validate.py` (which fails when prose
floors disagree with the `orca` pin, #512), `runtime/scripts/upstream_probe.py` (weekly
drift detection), `runtime/scripts/pin_review.py` (rug-pull diffing on pack bumps, #559),
and `scripts/install.sh`; shape and rug-pull review artifacts pinned by `tests/test_pins.py`.

Each entry carries `repo`, `commit` (full 40-char SHA), `version`, `witnessed` (YYYY-MM-DD),
`witness` (`live` or `source`), and `aliases` (tokens matched against `skills/*/SKILL.md`
`compatibility:` fields). The `orca` entry additionally records `witness_binary` and
`onpath_at_witness`.

Keys:

| `_about` | Contract: how `source` vs `live` witnessing works and which cadence owns each entry |
| `orca` | `stablyai/orca` runtime + CLI pin (re-witnessed by `pin-it`) |
| `gstack` | `garrytan/gstack` worker-playbook pack pin (requires a `docs/research/pin-reviews/gstack-<full-commit>.md` rug-pull review on bump) |
| `addyosmani` | `addyosmani/agent-skills` worker-playbook pack pin (requires a `docs/research/pin-reviews/addyosmani-<full-commit>.md` rug-pull review on bump) |
| `mattpocock` | `mattpocock/skills` worker-playbook pack pin (requires a `docs/research/pin-reviews/mattpocock-<full-commit>.md` rug-pull review on bump) |

> Why: when the pinned Orca floor or upstream pack commit lived in prose, the installer,
> the validator, and the pin record drifted apart silently. Centralizing `runtime/pins.json:orca`
> and the three pack keys (`runtime/pins.json:gstack`, `runtime/pins.json:addyosmani`,
> `runtime/pins.json:mattpocock`) lets `scripts/install.sh` read the floor at install time,
> `scripts/validate.py` reject stale version mentions, and `tests/test_pins.py` require a
> completed `runtime/scripts/pin_review.py` artifact for every pack commit recorded here.

## `quarantine.json`

The component deny-list: missions, playbooks, and upstream packs a human has declared
unusable (compromised, rug-pulled, unsafe). Source `runtime/quarantine.json`; enforced
by `scripts/validate.py` (catalog routing), `runtime/scripts/preflight.py --mission`
(run start), and `runtime/scripts/quarantine_check.py`; shape and matching pinned by
`tests/test_quarantine.py`.

Top-level keys: `_about` (the contract), `quarantined` (the list, empty by default).
Each entry carries `component` (`mission:<name>`, `playbook:<name>`, or
`pack:<pins.json key>`), `ref` (`*`, or a pack commit of at least 7 hex chars matched
by prefix either way), `reason`, `date` (YYYY-MM-DD), and `by` (`human:<who>` —
anything else is refused at parse). A quarantined mission's files stay in the catalog
as evidence while dispatch is refused; a quarantined playbook or pack ref still routed
to by the catalog fails validation until the references are removed or a human lifts
the entry.

## `watchdog.json`

Liveness-watchdog thresholds and rate limits for `runtime/scripts/watchdog.py`. Every
detection threshold lives here so coordinators tune without code edits; the script
refuses unknown keys, so a typo fails loud instead of silently holding a default. Source
`runtime/watchdog.json`.

Keys:

| `_about` | Provenance: generalized from the 2026-09-14 clean-sweep tracker run |
| `slow_after_s` | 600 — idle past this is SLOW |
| `hung_after_s` | 1800 — idle past this is HUNG |
| `wedge_frozen_s` | 1200 — transcript frozen past this beyond STOP (plus an unanswered nudge) is WEDGED |
| `max_nudges_per_dispatch` | 1 |
| `nudge_window_s` | 3600 — minimum spacing between nudges to one worker |
| `max_nudges_per_hour_per_worker` | 1 |
| `nudge_text` | The auto-nudge message |
| `nudge_command` | null — no transport configured; live mode refuses to run without one |

> Why: starting values are generalized from the 2026-09-14 clean-sweep tracker run
> (`runtime/watchdog.json:_about` names the two cases: a reviewer 60+ minutes idle with
> a transcript frozen 20+ minutes, a verdict worker wedged on a dead provider stream) —
> field-shaped, not derived, and tunable here without code edits. The single-nudge cap
> (`runtime/watchdog.json:max_nudges_per_dispatch`) exists because a nudge that goes
> unanswered is itself evidence: still-HUNG after one nudge escalates to a
> stop-redispatch recommendation rather than a second poke into the void.
