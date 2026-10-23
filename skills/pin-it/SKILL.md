---
name: pin-it
description: >-
  Maintainer-facing (the fleet's own Orca doctrine). Re-witness and re-pin the fleet's runtime-mechanics doctrine against the installed control-plane binary
  after an upgrade or a drift signal: enumerate every mechanics claim in runtime policies, scripts, and
  mission dispatch preambles, load the version-matched guides the binary serves, replay each claim live, and
  patch what lags — kept claims carry receipts, removed claims carry archived refutations. The unit is one
  mechanics claim. Use when "Orca updated", "re-pin the runtime contract", "policy lags practice", "the guides
  say otherwise", "our control-plane dispatch docs are stale", "a receipt shape appeared that the runtime
  guides don't describe". Not for docs that drifted from your own code or API contract (clean-sweep),
  dependency/framework upgrades (modernize-it), or a PR verdict (review-it).
license: MIT
compatibility: >-
  HARD dependency: Orca runtime + orchestration skill (Orca CLI) — the binary under audit; `orca
  skills get <name>` must work, and re-witness probes run against the live local runtime from a
  live Orca terminal. git. A worker playbook pack (mattpocock, addyosmani, gstack) — one router
  per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one runtime-mechanics claim
  state_machine: enumerate claims → load version-matched guides → replay live → keep-with-receipt or refute
  convergence: every enumerated claim carries a receipt or an archived refutation against the installed binary
  ordering: none between claims; the enumeration is frozen before any replay
  parking: PINNED-WITH-PARKED — a claim the binary cannot answer names why
  oracle: the installed control-plane binary and the version-matched guides it serves
---

# pin-it — doctrine that matches the binary

You are the **COORDINATOR** of a runtime-contract re-pin. "The mechanics we teach are the mechanics
the installed binary actually runs" is a user-facing outcome: a fleet whose policy layer teaches dead
command shapes corrupts real runs. **The installed binary is the source of truth; the version-matched
guides it serves (`orca skills get …`) are the map of what to probe — never the proof.** This
mission's job is to make the written doctrine provably equal to the binary's *observed* behaviour.
Composes `remediate-finding` (patch each stale claim), `acceptance-review` (build-blind review of
the doctrine patch), `compound-learn` (what drifted and why feeds the retro); rides
`evidence-manifest` (the claim inventory is the criteria denominator; every verdict binds receipts
to `head_sha`), `merge-serialization`, `reviewed-sha-freshness`, `ledger-contract`,
`liveness-resume`, `gate-classification`, `dispatch-lifecycle`, `sandbox-policy` (repo read probes
are PROFILE=ro; control-plane probes — run-create, worktree create, worker-start — MUTATE Orca
state and run in a scratch Orca worktree with full teardown: settle the run, release workers,
remove the worktree — teardown commands are claims too (re-witness before relying; if unsupported,
archive the worktree, never force-remove); never against the default branch or a live fleet's run
state), `attention-budget`, `orca-pin` (the pin record: read the prior pin + run pointer at start, rewrite both at close). Worker TASK pack: one of matt | addy | gstack — never co-mount.

## Terminal outcomes

- **PINNED** — every claim in the frozen inventory is CURRENT with a live receipt, and every patched
  claim's replacement text is receipt-backed at the merged SHA.
- **PINNED-WITH-PARKED** (degraded) — claims whose re-witness needs something the session cannot get (a remote
  host, a paid tier, a human-only surface, an unfixable-in-session precondition) are PARKED, each
  named with the exact probe it waits on; a parked claim's doctrine text is marked unverified,
  never silently kept.

## Pipeline

```
FREEZE the claim inventory: extract every mechanics claim from runtime/*.md, runtime/scripts/, and
  mission SKILL.md dispatch preambles — command shapes, receipt fields, lifecycle rules, error
  codes, scoping claims. SCOPE CUT: claims about the fleet's own policy (BASE ≠ default, ledger
  flags, reviewed-SHA freshness) are enforced by preflight.py / verify.py and are NOT in scope —
  re-witnessing fleet invariants against the control plane is a category error. CLAIM RECORD per
  unit: id · source file:line · claim text (verbatim) · probe command · expected receipt shape ·
  class · receipt path · disposition. Worked example: claim "check --wait returns ONE message per
  call" → probe: two workers settle, one consuming check → receipt shows a ≤50-message Delivery →
  STALE (the mechanism lives; its behaviour changed) → doctrine rewritten to Delivery-batch
  semantics. SUPERSEDED is for a mechanism that is GONE (unknown command / retired-alias recovery).
→ BOOTSTRAP integration BASE ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mission pin-it --base <BASE> --fork-point <sha>;
  BASE ≠ default — dispatch-lifecycle.md). Doctrine patches land on BASE, never on the default.
→ LOAD the version-matched guides from the INSTALLED binary; record the CLI version. Per topic run `skills get <topic>
  --references`, then `--reference <name>` for EACH (`--full` fallback): the contract lives there, not in the kernel.
→ RE-WITNESS each claim: replay it against the live runtime from a live Orca terminal (a bound
  coordinator terminal or ORCA_TERMINAL_HANDLE — orchestration calls fail with
  no_active_sender_terminal from a plain shell) and capture the verbatim receipt.
→ CLASSIFY per claim, from receipts only: CURRENT (receipt matches) · STALE (binary behaves
  differently — capture the actual receipt) · SUPERSEDED (mechanism gone — capture the
  *mechanism-level* refusal: unknown command, or a retired-alias recovery message naming the
  replacement; task/state refusals like `task_not_startable` are about the unit, not the
  mechanism, and never classify SUPERSEDED) · BLOCKED-BY-SUBSTRATE (the probe's precondition
  failed — no sender terminal, untrusted worktree, expired credentials, absent device: the
  receipt says nothing about the claim). Substrate blocks: fix the precondition and re-probe; a
  human-only precondition → PARK. NEVER let a substrate failure reclassify a claim — that rewrites
  doctrine to "the mechanism does not exist" when the session merely could not run it.
→ PATCH (rw workers, remediate-finding): stale/superseded doctrine rewritten to the receipted
  behaviour, one claim per unit, citing the receipt. Deleting a claim requires its refutation
  receipt (the old shape demonstrated failing against the live binary). remediate-finding's
  failing-first requirement instantiates for a docs-only claim as the archived refutation receipt
  (the pre-patch probe RED), not a repo test — no test binds prose.
→ build-blind REVIEW (acceptance-review: every edited line traces to a receipt; a doctrine line
  with no receipt is a finding) → LAND (merge-serialization with reviewed-sha-freshness).
→ VERDICT: PINNED, or PINNED-WITH-PARKED with the park register.
```

## Convergence proof (definition of done)

Every claim in the frozen inventory is accounted for: CURRENT with a captured receipt, PATCHED with
the replacement doctrine citing its receipts, REMOVED with an archived refutation receipt, or
PARKED with the exact probe it waits on. The claim-level negative control is the §1 doctrine-patch
carve-out (evidence-manifest.md): the archived pre-patch refutation receipt, re-run by the verifier
post-merge — a patch whose old text still probes GREEN at `head_sha` is not proven. Receipts name
the CLI version they were captured from; the verifier re-runs a ≥10% sample of probes at
`head_sha`. The inventory never shrank mid-run — a claim no unit reached is unassigned work, not
silence. Repo gates (validator, tests) green at the landing SHA.

## Ledger + supervision

Ledger header at T0 per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP`
— row schema per `ledger-contract.md`, WIP sized to `attention-budget.md`, one statement so the two
cannot drift (#383). WIP: builders=<n> reviewers=<n> (`-` if N/A; SOURCE = the claim-inventory digest + the installed CLI version). One row per claim:
id, source file:line, class, receipt path, patch PR, verdict. Re-witness probes are cheap and
parallel within `attention-budget`; PATCH waves are doc-mutation units (≤3 builders, 1 reviewer per
3 builders). Stalls → `liveness-resume.md` WATCH; death → RESUME (ledger-scoped; receipts on disk
are the re-derivation source). First run here: the 2026-09-09 adoption audit
(`docs/research/2026-09-09-upstream-adoption-audit.md`) is the orchestration surface's pre-cut
claim inventory.

## Anti-patterns

Classifying from the version-matched guide without replaying the claim (guides drift too).
Classifying from a substrate-failed receipt (BLOCKED-BY-SUBSTRATE is a precondition verdict, never
evidence about the mechanism — the 2026-09-09 field run's `agent_prompt_stalled` /
`no_active_sender_terminal` are exactly this trap). Fleet-policy invariants never enter the
inventory (preflight/verify-enforced; the binary can't reject them). Wholesale doctrine rewrites
("modernise the page") — the unit is the claim. Dropping a claim because its probe is awkward
(that is a PARK, named). Shrinking the inventory mid-run. Marking doctrine current because a run
"worked" — a run that succeeded through an undocumented fallback path is evidence FOR drift, not
against it. Control-plane probes without teardown (orphaned runs/terminals/worktrees in the local
Orca state).

## Related

`modernize-it` (dependency/framework versions, repo-suite oracle; its `CURRENT-WITH-PINNED` is a
*dependency version* pin — unrelated to this mission's `PINNED` doctrine terminal), `clean-sweep`
(a findings backlog; doc-claims mode is prose claims against repo state, not runtime mechanics
against a binary), `review-it` (a per-diff verdict), `dispatch-lifecycle` (the subject matter;
pin-it is what keeps it true).

Bundled copy of `pin-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
