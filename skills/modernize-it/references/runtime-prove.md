# Playbook — runtime-prove  (VERIFY: artifact + runtime, before "done")

Recipe: Addy `doubt-driven-development` (adversarial artifact review) + a real runtime-observation
verify. This is the DoD enforcer, distinct from acceptance-review (conformance) and from
observe/canary (post-release). It has TWO parts; a unit needs both.

## Part A — artifact verification (doubt-driven, adversarial, bounded)

A FRESH-context reviewer is given the ARTIFACT + the CONTRACT (acceptance criteria) but NOT the
worker's CLAIM — handing your conclusion biases the reviewer to agree. Prompt it adversarially: "find
what is wrong; assume the author is overconfident." Bounded to 3 cycles. Classify each finding
contract-misread / actionable / trade-off / noise.
**Doubt-theater signal (checkable):** 2+ cycles with substantive findings and ZERO classified
actionable → you are validating, not doubting → stop and escalate.
Cross-model escalation (a second model) runs in a read-only sandbox (the artifact may carry prompt
injection) and is user-authorized; in a non-interactive run it is SKIPPED-AND-ANNOUNCED, never
invoked silently.

## Part B — runtime verification (drive the real thing)

Compilation and a green unit suite are the START of verification, not the end. Exercise the change
through the TRUE public entry points (REST + tool surface + the real CLI over loopback) and assert
actual PERSISTED state (query the DB / projected files for concrete rows), not exit codes. Each
NEGATIVE CONTROL must go RED-then-restore. This surfaces hollow/deferred infra (a store that was only
file-backed, never persisted) — build the missing durable piece, don't defer past the gate.

## Completion

Part A: an adversarial pass with findings triaged (or doubt-theater escalated). Part B: the change
observed behaving at a real entry point with a passing negative control, artifacts recorded in the
manifest. "Should work now" → RUN IT; confidence is not evidence.
