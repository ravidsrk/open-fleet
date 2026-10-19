---
name: attest-it
description: >-
  Prove a codebase or change-set conforms to a standard — EU AI Act Art-12/50, SOC 2, NIST SSDF —
  with auditor-grade, independently re-derived evidence, or name the gaps. The unit is one
  obligation from a FROZEN standard catalog (standard@version), not a discovered finding:
  enumerate the obligations, gather evidence bound to authoritative state for each, have an
  independent session re-derive it, and mark each control VERIFIED or GAP. Use when "prove
  compliance", "conformance", "audit-ready evidence", "SOC 2 / EU AI Act / NIST SSDF attestation",
  "regulatory audit trail". Not for a security exploit loop (harden-it), a PR merge verdict
  (review-it), or closing a discovered backlog (clean-sweep).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter). git + gh; a FROZEN standard catalog
  (standard@version) as the denominator. A review/verify worker playbook (addyosmani specialists,
  mattpocock code-review, gstack review army) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one obligation from a frozen standard@version catalog
  state_machine: freeze the catalog → gather bound evidence → independent re-derivation → VERIFIED or GAP
  convergence: every obligation in the frozen catalog is VERIFIED or a named GAP with an owner
  ordering: none between obligations; evidence gathering precedes re-derivation
  parking: CONFORMANT-WITH-GAPS — each gap names its owner and remediation reference
  oracle: an independent session re-deriving the evidence from authoritative state
---

# attest-it — evidence-bound conformance to a frozen standard

You are the **COORDINATOR** of an evidence-bound conformance run. "Prove this conforms to standard X,
or name the gaps" is a user-facing outcome AND an audit artifact: each control is either satisfied with
evidence an independent session re-derives, or it is a named GAP parked to a human/legal owner — never
a silent pass. Composes `decompose-dag`, `acceptance-review`, `research-brief` (catalog sourcing),
`completion-audit` (an EXTERNAL-STATE control is a GAP, never an assumed pass), `human-handoff`
(every GAP is filed with an artifact, an owner, and a verify-complete observation),
`publish-evidence` (the attestation bundle leaves the tree as a versioned link); rides
`evidence-manifest` (each control's
evidence binds to authoritative state via the Art-12/50 provenance block and is re-derived, not
narrated), `gate-classification` (a GAP that needs a policy/spend/legal decision is a one-way human
door), `sandbox-policy` (`PROFILE=ro` for evidence gathering), `threat-model` (the fleet's own
trust assumptions and four boundaries — the scoping input when the system under assessment is a
software factory), `ledger-contract` (the obligation
ledger), `liveness-resume` (DAG-scoped RESUME). Worker TASK pack: one of matt | addy | gstack — never co-mount.

## Terminal outcomes

- **CONFORMANT** — every obligation in the frozen catalog is VERIFIED: evidence bound to authoritative
  state, independently re-derived, no control marked satisfied without a linked artifact.
- **CONFORMANT-WITH-GAPS** (degraded) — one or more obligations are GAPs, each parked to a named human/legal owner
  with the missing evidence stated. A GAP is a first-class terminal, not a failure to hide.

## Pipeline

```
REFUSE-IF-QUARANTINED (runtime/scripts/preflight.py --mode readonly --mission attest-it) → FREEZE the denominator: pick standard@version and its SOURCE — the standard's own text or a
  human-supplied obligation catalog, as a file/URL at a digest; obligations are enumerated FROM that
  document, never from model memory (a recalled SOC 2 / SSDF control list is a hallucinated
  denominator) — then enumerate into a DAG (decompose-dag). The set is frozen at the digest — the run
  cannot shrink it.
  → EVIDENCE (per obligation, ro workers): gather the artifact that satisfies the control (a log field,
    a policy version, a test outcome, a scan result), bound to authoritative state in an evidence
    manifest with the provenance block (spec_version · model · reviewer · retention · standard).
  → RE-DERIVE (independent session, acceptance-review): a different session confirms each control's
    evidence against authoritative state — deterministically where possible (verify.py), never the
    gatherer's own narration. The re-derivation confirms each control's `provenance.standard` +
    `spec_version` EQUAL the FROZEN catalog's `standard@version` (verify.py's `check_provenance`
    enforces the Art-12/50 audit fields are present); a control evidenced against a different version,
    or with no re-derivable artifact, is a GAP, not a pass.
  → AGGREGATE: every obligation VERIFIED or GAP; GAPs carry the missing evidence + a human/legal owner.
  → PUBLISH the attestation bundle as a versioned link (`publish-evidence`).
  → VERDICT: CONFORMANT, or CONFORMANT-WITH-GAPS with the gap register.
```

## Convergence proof (definition of done)

Every obligation in the frozen `standard@version` catalog is accounted for: the union of unit contracts
equals the standard's obligation set (no obligation unassigned), each VERIFIED control carries evidence
bound to authoritative state and independently re-derived (not the gatherer's narration), and each GAP
is named with its missing evidence and a human/legal owner. The verdict is CONFORMANT or
CONFORMANT-WITH-GAPS; advancing past a degraded terminal (accepting residual gaps) is a one-way human
gate. No obligation is silently dropped.

## Ledger + supervision

Ledger header at T0 — the full canonical `liveness-resume.md` header
(`RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE: <frozen catalog ref+digest> · WIP: builders=<n> reviewers=<n>`) —
plus one row per obligation (`obligation-id → task → VERIFIED | GAP`), written before dispatch so an
interrupted run is recoverable, not a resume orphan (`RUN` / `COORDINATOR` are what RESUME dies
without). Stalls / death / compaction → `liveness-resume.md` (death → RESUME; compaction → write the
`CONTEXT HANDOFF` block, then RESUME): RESUME's scope is that header + the obligation rows,
git-verified — it reconstructs the DAG and re-enumerates which obligations were dispatched, VERIFIED,
or GAP, so the convergence verdict is never trusted from memory.

## Anti-patterns

Marking a control satisfied on the gatherer's word (evidence must be re-derived independently — the
whole point). Shrinking the obligation set to the ones you can pass (the denominator is frozen at a
version digest). Treating a GAP as a failure to bury instead of a named, parked terminal. Confusing
attest-it with harden-it (attest proves conformance to a standard; harden runs an exploit→fix→re-attack
loop) or review-it (a per-PR merge verdict, not a standard's obligation set). Re-using an evidence
artifact whose `provenance.spec_version` no longer matches the frozen standard version. Enumerating
obligations from model memory (the catalog is a sourced document at a digest; a plausible control list
is not the standard).

## Related

`review-it` (a per-PR verdict, not a standard's obligations), `harden-it` (the security exploit loop),
`clean-sweep` (close a discovered backlog); `evidence-manifest` (the Art-12/50 provenance block attest-it
attests against), `mission-scheduling` (report-heavy, schedules cleanly as an unattended conformance sweep).
