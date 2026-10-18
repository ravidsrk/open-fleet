# Playbook — risk-review  (REVIEW: scope-gated specialist lenses)

Recipe: Addy specialist skills (security, performance, accessibility, data-migration), scope-gated with adaptive suppression as stated below. NOT run on every diff — DISPATCHED when the change surface triggers the lens.

## Two invocation modes

Diff-triggered (the default, below) — a lens runs when the change surface signals it. TREE-WIDE
(harden-it's audit waves): the fixed point is the whole codebase at the BASE head; scope-gating is
bypassed and every requested lens runs over the full surface.

## Dispatch rule (scope-gated, diff-triggered mode)

Compute the signals with `runtime/scripts/diff_scope.py --json --strict`, never by eye: it fail-louds on a base it cannot resolve AND
on any path it could not classify, so neither "we could not look" nor "we looked at half of it" can read as "nothing to look at" (#284, #314).
Run a lens only when the diff signals it (auth/query/route/dep change → security; render/query/bundle
→ perf; component/markup → a11y; schema/migration → data-migration; public route/contract/interface
change → api-contract; new abstraction/helper/module the diff did not strictly need → simplification).
A change that stores, logs, exports, or forwards personal data triggers privacy.
Adaptive gating: a lens with 0 findings across its last 10+ dispatches auto-gates off; security,
privacy, and data-migration are NEVER_GATE (their value is the miss they'd catch).

The tally is never coordinator memory — it lives in the target repo's DECISIONS log (`docs/DECISIONS.md`, ledger-contract.md): committed state that survives a crashed run and is shared across runs and coordinators. Every lens dispatch appends one DECISIONS line with id `lens-tally:<lens>`, class `mechanical`, and the dispatch's finding count as its answer. The gate check runs BEFORE dispatching a lens: read that lens's tally lines newest-first; 10+ consecutive zeros → auto-gate off, appended as its own `lens-gate:<lens>` decision line; any nonzero count resets the streak. Two coordinators reading the same log reach the same gate verdict.

## The lenses (each a fresh-context worker, its own protocol)

- **Security:** threat-model-first (STRIDE per trust boundary) → OWASP Top 10 + OWASP LLM Top 10 +
  supply-chain. Treat model output as untrusted (no eval/SQL/shell/innerHTML); block dep scripts
  before first run, never `audit fix --force`; SSRF allowlist with a TOCTOU caveat. Rate limiting on
  auth endpoints must hold across instances — an in-memory limiter in front of >1 instance is a
  finding. Any destructive-path operation (delete/cleanup/migration teardown) validates its TARGET
  before acting: allowlisted root after symlink resolution, a depth floor below it, and ownership
  evidence read first — a shape check is not authorization. These checks are the FILESYSTEM form;
  for other destructive targets the equivalents are: a DB migration teardown → named environment
  allowlist + object identity re-read at execution + ownership proof; a cloud resource →
  account/project allowlist + resource identity (ARN/id) verified live. Two caveats, because the
  check reads stronger than it is: a marker written INSIDE the tree is self-attestation (anything
  that can write there can write the marker), so the expected owner must come from authenticated
  state and the marker needs integrity protection; and resolving a path then acting on the NAME is
  a check/use race wherever another process can swap an ancestor — hold the target by descriptor,
  or prove the hierarchy cannot change. When path-scoped (`--paths`), report any skipped/missing path
  in the scope header (never drop silently). Every finding needs a concrete step-by-step exploit
  scenario (never test live APIs); one verified finding → grep the whole tree for VARIANTS. (Full audit→re-attack loop is `harden-it`; this is the bounded review lens.)
- **Performance:** measure-first (no optimizing without a baseline); symptom→cause tree (slow load →
  bundle vs TTFB); CWV targets; before→after to its metric contract, and a delta `explain-the-number` calls inconclusive is not measured; add a CI
  regression budget (GUARD). Backend red flags: N+1 fetch patterns; an index added with no query
  plan before and after; a cache key omitting an input the response depends on (tenant, locale,
  viewer); a cache with no staleness window or invalidation; a pool size raised in answer to
  exhaustion without finding what holds connections; a list endpoint with no pagination. Reviewing
  SOURCE only (no baseline reachable) → every finding is labelled **potential impact**, never a
  measured regression, and carries the measurement that would confirm it. Keep-or-revert
  discipline: a NEUTRAL result is a revert, not a keep —
  and every attempt, reverted or not, is ledgered so a dead idea is never re-tried next quarter.
- **Accessibility:** WCAG 2.2 AA (keyboard, ARIA, focus, 4.5:1 contrast, target-size, focus-appearance, empty/error/loading states); a 2.2-only success criterion this per-diff lens cannot judge is recorded as a PARKED finding routed to `access-it` — the verdict names it, never a silent GO
  + the anti-AI-aesthetic check (no purple/gradient/rounded-2xl slop, no lorem hero).
- **Data-migration:** expand→migrate→contract (additive first, destructive last-and-alone); every
  migration has a TESTED down path written and run before merge; a schema change and its dependent
  code never ship in one deploy (Hyrum's Law + the Churn Rule).
- **API-contract:** public routes/interfaces changed → breaking-change check (removed/renamed
  fields, tightened validation, changed defaults, error-shape drift); versioning/deprecation path
  named for every break; consumer-compatibility evidence quoted, not assumed. State-machine check:
  when a diff adds/changes a persisted `status`/`state`/`phase`/`kind` enum or lifecycle transition,
  verify a `kind × action → expected row` matrix with a test `path:line` per transition and round-trip
  symmetry (e.g., `pause→resume`, `archive→unarchive`) restoring invariants without stale residue.
  Idempotency, where a retry can repeat an effect: the key is derived from the INTENT (client- or
  event-generated, stable across retries, distinct across intents), the claim is ATOMIC (a unique
  constraint picks the winner — check-then-act is a race), the payload is hashed and a reused key
  with a different body fails loudly, the in-flight-duplicate policy is stated (reject / bounded wait
  / pending+status), and retention outlives the LONGEST redelivery chain (dead-letter replays, dispute windows).
- **Privacy** (NEVER_GATE, paired with security): security asks "can an attacker read it"; privacy
  asks "should we hold it at all, and for how long". Every personal-data field added or moved is
  CLASSIFIED (non-personal / personal / sensitive), collected against a STATED PURPOSE ("might be
  useful later" is latent breach scope, not a purpose), given a retention limit with a working
  deletion path that covers the copies (backups, caches, search indexes, analytics), and — for any
  third-party or model-vendor forwarding — gated on auditable consent. PII in telemetry or logs is
  a finding. A privacy finding whose fix exceeds this diff routes out as a mission-level item, not
  a silent nit.
- **Simplification** (advisory): hunts structure the diff did not need — new abstraction over one
  caller, helper used once, speculative generality, wrapper that adds no behavior. Findings are
  advisory-severity by default; "delete the unrequested structure" is the fix shape.

## Completion

Every triggered lens ran (or is a recorded gate-off); each finding names its lens, severity, and (for
security) an exploit scenario. A clearance that rests on one safety fact is unproven until a run shows it; for a runtime-behavior `BLOCKER`/`Critical` claim, a review worker may run an ephemeral reproduction probe in a doctor-verified isolated environment recipe (`vm recipe doctor` / `orca environment`) without mutating the reviewed worktree, and any runtime `BLOCKER` claim not backed by an executed probe or failing test receipt is labeled `STATIC_ONLY`. Findings emit in the shared schema for the mission's ledger.
