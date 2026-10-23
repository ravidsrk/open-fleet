# Runtime policy — mission chaining (sequential, gated, minimal)

"Make this repo production-ready" spans more than one mission (harden-it, then prove-it, then
ship-it). Chains are how a coordinator runs that — and the predecessor repo proved the failure
mode: a YAML campaign engine with conditional edges where 4 of 8 presets rotted as stubs and
every chain that actually ran was linear with halt-on-blocked. So this policy is deliberately
small. Sequential only. No DAG, no expression language, no preset catalog.

## The chain contract

- **Declare the chain up front**, in the ledger header: the mission sequence AND, per link, the
  set of terminal states allowed to proceed. Example:
  `harden-it[CLEAN] → prove-it[COVERED] → ship-it[PROMOTION_READY]`.
- **The gate between missions is the previous mission's named terminal state, backed by its
  verified evidence** (evidence-manifest.md). An audit GATES the chain — there is no
  "continue anyway" edge. A terminal is **degraded** — it STOPS the chain and parks it (advancing is
  a one-way human gate, gate-classification.md, recorded in the ledger) — if its name carries a
  degradation marker (`-WITH-PARKED`, `-WITH-OPEN-ITEMS`, `-WITH-GAPS`, `-WITH-MANUAL-PARKED`,
  `-WITH-BLOCKED`, `-WITH-QUARANTINE`, `-WITH-PINNED`) OR is `NO-GO` / `INCONCLUSIVE` / `ABANDONED`
  (migrate-it's rolled-back terminal: the expand was undone, so nothing landed to build a next leg
  on). Every other
  named terminal is **clean** and may proceed when the chain named it (e.g. `BUILT`, `RELEASED`, `DRY`,
  `CLEAN`, `STABLE`, `COVERED`, `CURRENT`, `WITHIN-BUDGET`, `CONFORMANT`, `CONTRIBUTED`, `MAPPED`,
  `GO`, `DIAGNOSED`), including **handoff terminals** such as
  `DIAGNOSED-WITH-HANDOFF` and `awaiting-maintainer-merge` (oss-contribute's normal terminal: your
  part is done, an upstream human owns the merge) — a handoff, not a degradation. The rule classifies
  every mission's terminal, so a chaining coordinator is never left guessing. Run it, don't
  eyeball it: `"$OPEN_FLEET_ROOT/runtime/scripts/chain_check.py" gate --allowed <declared set> <terminal>` at each
  boundary (`audit` keeps every mission's "(degraded)" labels agreeing with this rule).
- **One mission active per repo at a time.** Each link is a FULL run: its own preflight, its own
  integration BASE, its own convergence proof. Carrying a BASE from one mission into the next is
  an explicit human decision, never a default.
- **Chains are human-paced at every link boundary.** Leg N's PROMOTION is BASE→DEFAULT — landing
  its integration BASE on the repo's default branch — and that is the one-way human gate
  (gate-classification.md's closing rule; merge-serialization.md). Merging a unit INTO the BASE is
  the conductor's ordinary agent merge, the no-gh local-merge lane included, and is NOT that gate.
  Leg N+1 forks from the promoted DEFAULT, so between any two links — every boundary, not just the
  first — the chain STOPS and waits for a human. That is the NORMAL case, not a degraded one: the
  stop rules above classify mission TERMINALS, and a leg that ended on a clean terminal still
  cannot hand leg N+1 a BASE it is not allowed to create.
- **The wait has a name: `PARKED-AT-PROMOTION`.** It is a CHAIN state, recorded in the ledger
  header beside the link it stopped at — never a mission terminal, so leg N's own terminal stands
  as the mission named it. It is the expected outcome of any leg that finishes in a lane that
  cannot PROMOTE (headless, `--no-gh`, scratch or local-only target) — such a lane may still
  integrate its units into BASE: carry PRODUCED, promotion OWED. Resuming the park REQUIRES
  exactly one of two facts, each recorded in the ledger; nothing else is sufficient:
  1. a **landed promotion SHA** — leg N's integration BASE tip is an ancestor of the DEFAULT
     branch (`git merge-base --is-ancestor <base-tip> <default-ref>`, where `<default-ref>` is
     `origin/<default>` for a REMOTE target — REFRESHED immediately before the check
     (`git fetch origin <default>`), with the resolved default SHA written down, on
     preflight.py's own contract that an online default resolves through
     `refs/remotes/origin/<branch>` and never a possibly stale local namesake; a `<default-ref>`
     whose freshness cannot be established leaves the promotion UNPROVEN and the chain parked,
     never landed — and a valid LOCAL ref, the local default branch, for an explicitly OFFLINE
     target with no remote, never a nonexistent `origin/…`); the ancestry subject is leg N's own
     completed BASE tip and no other commit; leg N+1 forks from that promoted DEFAULT; or
  2. a recorded **BASE-carry grant** — the named human's explicit decision (the carry-over above)
     that leg N+1 may fork leg N's UNPROMOTED BASE tip, with the granted SHA written down.
  An agent-executed promotion is neither. A coordinator may not resume its own promotion park.
- **Deferral carry:** mission N's parked items, backlog file, and noticed-but-not-touched list
  are handed to mission N+1 as enumeration INPUT — findings to triage, never pre-confirmed work.
  This is the generalization of the existing hard-wired handoffs (map-it's frozen DAG feeding
  ship-it; prove-it's surfaced bugs feeding clean-sweep).
- **The carry has ONE shape: the handoff log.** One Markdown file per chain, `handoff-log`, written
  beside the chain report and named in the ledger header so a consumer finds it without reading the
  run. Two sections, both required:
  1. a **carry table**, one row per carried item — `carry id` (stable, chain-scoped: `H1`, `H2`, …)
     · `from` (leg number + source class: parked / backlog / noticed-not-touched) · `content` (the
     item, pinned to file:line at that leg's cited SHA) · `input status` for the consuming leg
     (`OWED` until leg N+1 triages it; then its finding id and triage verdict).
  2. a **gate record**, one entry per inter-mission gate — which gate, its state, the human who
     owns it, and what resumes it (for a promotion park, the two facts above).
  Nothing deferred is written as an explicit empty carry plus the re-read that established it: a
  MISSING handoff log is an unfinished chain, never an empty one. Worked exemplar:
  docs/reports/chaining-2026-09-16/handoff-log.md — written as that run's PROPOSED shape, which
  predates this clause; it is ADOPTED here, so the shape above is doctrine and not a proposal.
- **Local-only targets must ship their bytes.** "A second person can re-derive each leg's outcome
  from the cited SHAs" holds only where those SHAs resolve FOR THAT PERSON. When a leg's target has
  no remote — a scratch repo, a local fixture, an air-gapped checkout — SHA citation re-derives
  nothing and the chain report is unverifiable on its own terms. Such a leg is complete only once
  the chain publishes one of two things, named in the report, and is INCOMPLETE without one: a
  reachable **pushed mirror** of the target (the remote and the pushed refs written down), or
  embedded **reconstruction artifacts** committed beside the chain report that are
  COMMIT-PRESERVING — a self-contained `git bundle` of the leg's refs, or an equivalent that
  demonstrably reproduces every cited commit and its ancestry. Seed sources plus the leg's full
  diff recover file bytes only, never the commit objects, so they are SUPPLEMENTAL and never
  sufficient on their own — the exemplar's own
  docs/reports/chaining-2026-09-16/leg1/RESTORE.md draws exactly that line. Every published
  artifact is hashed into the run-close integrity inventory (evidence-manifest.md), so a later
  audit can tell the bytes have not moved.
- **Cross-repo chains do not exist.** One coordinator per repo; a program spanning repos is
  separate coordinator sessions a human sequences.

## Completion

The chain report names, per link: the mission, its terminal state, the verification result, and
what was carried forward. A chain that stopped early names the gate it stopped at — a stopped
chain is a correct outcome, not a failure to hide.
