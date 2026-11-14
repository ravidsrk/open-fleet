# Playbook — triage-findings  (candidate findings → VERIFIED, with the noise removed)

Recipe: gstack `cso` (v2) false-positive filtering + active verification + parallel independent
verifiers, and the review-army dispatch shape. cso v3 dropped its confidence gate and exclusions
upstream: §1–§2 are fleet rules, applied to a v3 worker's output as to any scanner's. A scanner emits candidates; this playbook decides
which of them are findings. It sits between a lens or audit wave and the remediate-finding loop, and it
has no fix authority.

## 1. Confidence gate (declared per run, not per finding)

The mission declares the mode at T0 and it does not move mid-run.

- **Gated (default):** report only candidates at high confidence — a concrete exploit path or a
  clear instance of a known-exploitable pattern. Below the bar: not reported.
- **Comprehensive:** a low bar that filters only true noise (test fixtures, docs, placeholders) and
  admits anything that might be real. Everything admitted below the gated bar is labelled
  `TENTATIVE` and is never presented alongside confirmed findings without that label.

## 2. Hard exclusions (stack-neutral)

Discard a candidate that is only: resource exhaustion / rate-limit absence; credentials at rest
that are already encrypted and permissioned; memory or descriptor pressure; input validation on a
non-security-critical field with no demonstrated impact; a memory-safety claim in a memory-safe
language; a race or timing claim with no concrete path; a dependency advisory with no reachable
call (that belongs to the dependency lens, not a per-finding report); a file that is only a test
fixture and is imported by no production code; unsanitized input reaching a LOG; absence of audit
logging; weak randomness outside a security context; a "missing hardening measure" with no concrete
vulnerability; a prose documentation file.

**Named carve-outs, because a blanket exclusion swallows real classes.** Cost/spend amplification
is financial risk, not resource exhaustion. CI/CD pipeline findings (unpinned third-party actions,
privileged-trigger workflows checking out untrusted refs, script injection, secret exposure,
missing ownership on workflow files) are concrete risks, not missing hardening. Files that are
executable agent instructions are CODE, not documentation, whatever their extension — a supply-chain
finding in one is never excluded as "a markdown file".

## 3. Precedents (the calibration list)

Logging a secret is a finding; logging a URL or non-identifying data is not. Unguessable identifiers
need no validation. Process environment and command-line flags are trusted input. Auto-escaping UI
frameworks are safe except at their explicit escape hatches. Client-side code is not the place
authorization lives — the absence there is not the finding, the absence on the server is. Shell
injection needs a concrete untrusted-input path. A lockfile untracked is a finding for an
application, not for a library. A container running as root is a finding in a production image, not
in a local development compose file. Extend this list per repo through DECISIONS lines; a precedent
is repo state, never worker memory.

## 4. Active verification, without touching anything live

For each surviving candidate, PROVE it by tracing code, never by exercising a live system: check a
secret against its real key SHAPE rather than an API; trace a handler chain to see whether
signature verification exists anywhere in it; trace URL construction to see whether user input can
reach an internal host; parse the workflow file to see what actually gets checked out; check
whether the vulnerable dependency function is directly called. Mark each candidate:

- **VERIFIED** — confirmed by tracing or a safe local test.
- **UNVERIFIED** — pattern match only, with the reason it could not be confirmed and what would.
- **TENTATIVE** — admitted under the comprehensive bar, below the gated bar.

## 5. Independent verifiers (anti-anchoring, mechanical)

Each candidate goes to a SEPARATE fresh-context worker that receives `file:line` and the filter
rules above — and NOTHING else: not the scanner's reasoning, not its severity, not its narrative.
The verifier reads the code and answers independently; below the bar it must say why it is not
real. Run the verifiers in parallel and let them finish before the report. A candidate whose
verifier scores below the run's bar is discarded, with the verifier's reason kept. If independent
verifiers cannot be dispatched, that is a recorded degradation on every finding in the run
("self-verified — no independent verifier"), never a silent equivalence: a scanner agreeing with
itself is one opinion.

## 6. Variant analysis

Every VERIFIED finding is a pattern, not an instance. Extract the pattern and grep the whole tree
for it; report each hit as its own finding linked to the original. One confirmed instance with no
variant search is an incomplete finding.

## Completion

The mode and its bar are recorded; every candidate is VERIFIED, UNVERIFIED, TENTATIVE, or
discarded-with-a-reason; every reported finding quotes its motivating line and names `file:line`;
every VERIFIED finding has a variant search with its result; every verifier ran in a session that
did not produce the candidate; degradations are stated on the findings they affect. Findings leave
here as input to the remediate-finding loop — nothing is fixed from inside this playbook.
