# Agent Baseline self-assessment — 2026-10-14

Dated snapshot: verdicts describe this repo as found on 2026-10-14; re-derive before
citing after that date.

orca-fleet assessed against [Agent Baseline](https://github.com/agentbaseline/agentbaseline)
v1.0-draft (six outcomes, 35 controls) and its companion paper, *The Secure Software
Factory: A Reference Architecture* v1. Frozen denominator:
`whitepaper/controls.yaml` at agentbaseline commit
`d842a1bb34a42e9d7c0d54a1b12ead9e0e59e283`, sha256
`06cd3966513c595b7cb455caebc01d9b0c5907f168b7e97ab3b98e1f5c56ae8f`. Identifiers below are
the baseline's bare IDs, cited as `DIS-01 (Agent Baseline v1.0-draft)`; they are `draft`
until that project's v1.0 freeze and are a namespace here, never our own vocabulary.
Control titles © the Agent Baseline authors (prose CC BY 4.0, `controls.yaml` Apache-2.0).

**What this is and is not.** This is a coordinator-authored assessment in `attest-it`'s
shape — frozen catalog, per-obligation verdict — performed by reading this repo's
enforcing artifacts. It is **not** an `attest-it` fleet run: no run report binds it, and
it advances no mission's proof tier. VERIFIED means an enforcing artifact exists in-tree
and is exercised (named in the row); anything short of the full requirement is a GAP,
with the met part stated. Tracking issue: #557.

## Summary

| Outcome | VERIFIED | GAP |
|---|---|---|
| Discover (DIS) | 0 | 7 |
| Constrain (CON) | 0 | 4 |
| Authorize (AUT) | 1 | 8 |
| Observe (OBS) | 1 | 5 |
| Validate (VAL) | 3 | 1 |
| Respond (RES) | 2 | 3 |

The fleet is evidence-strong and boundary-hardening. It proves what a unit did — SHA-bound
manifests, executed negative controls, run reports that re-hash — better than the
baseline asks, and since the 2026-10-17 follow-through (#558–#563) it also enforces
fail-closed component quarantine (`RES-02`), line-by-line upstream rug-pull reviews (`RES-05`),
adversarial prompt-injection drills (`VAL-01`), deny-hook egress gating (`#561`), and
measured escape probing (`#562`) alongside Orca v1.4.229 OS-level process/memory ceilings.
`runtime/threat-model.md` states the four boundaries and grades each; this file is the per-control detail.

## Discover

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| DIS-01 | Authoritative agent registry | GAP | Definitions authoritative: 22 missions as `skills/<name>/SKILL.md`, identity enforced by `scripts/validate.py`. No registry of deployments/instances beyond per-run ledgers. |
| DIS-02 | Ownership and risk context | GAP | No owner or risk-class field per mission; risk is handled by lanes/profiles at dispatch, not recorded per agent. Single-maintainer repo mitigates socially only. |
| DIS-03 | Status and decision history | GAP | Proof tiers + DECISIONS logs + run reports give decision history; no exception records with owner/expiry. |
| DIS-04 | Authoritative component registry | GAP | `runtime/pins.json` inventories upstream packs + Orca (source, commit, version, witness date); playbooks/runtime inventoried by the validator. Models are per-manifest declarations, not a registry. |
| DIS-05 | Agent composition mapping | GAP | Composition declared per mission (`Composes …; rides …`, validator-resolved, one pack per worker) and reverse-queried on quarantine via `quarantine_check.py` (#558). Runtime-resolved model versions remain per-manifest rather than centrally reconciled. |
| DIS-06 | Effective-access mapping | GAP | Effective access is the host's ambient access, nowhere mapped per agent or profile. |
| DIS-07 | Automated discovery and reconciliation | GAP | The plugin witness reconciles an installed copy once, by hand; no continuous registry-vs-observed reconciliation. |

## Constrain

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| CON-01 | Admission enforcement | GAP | The validator blocks a malformed catalog; spawn opt-ins (`ORCA_COORD_ALLOW_*`) fail closed. No risk-classified admission step for a new mission/component. |
| CON-02 | Toxic capability combinations | GAP | Real partial controls: one worker-pack per worker, `guard_text.py` fence + data-never-instructions, `ro` forbidding mutation. No systematic modelling of input→data→egress combinations. |
| CON-03 | Isolated and confined execution | GAP | `rw` = bypass flags + worktree + fail-closed string-match deny-hook probed by `tests/test_escape_probe.py` (#562), plus Orca v1.4.229 `orca serve` OS-level process/memory ceilings (`ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX`); the `danger` ephemeral-VM lane remains refused until prelaunch placement binding lands. |
| CON-04 | Use-case-scoped capability profiles | GAP | Profiles (`ro`/`rw`/`danger`) are versioned in `runtime/sandbox-policy.md` and their effect recorded (`launch.effective`); not signed or tamper-evident, and scope is coarse (whole-host shell). |

## Authorize

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| AUT-01 | Distinct identity and action attribution | GAP | Units bind worker, coordinator, run, task, SHAs (evidence manifest, ledgers, signed dispatch records), and the deny-hook refuses unreceipted `gh` writes (`egress.py`, #561). Remaining gap: where the hook is not wired in host settings, receipting is coordinator discipline checked at close. |
| AUT-02 | Purpose and task-bound authority | GAP | Coordinator signs the unit's contract digest + class (ed25519, `dispatch-sign.py`); the worker cannot shrink its denominator. No time-bounded grants; resource scoping is doctrinal. |
| AUT-03 | Delegation attenuation | GAP | Attenuation is by profile/lane convention; technically a worker holds the same ambient authority as the coordinator's shell. |
| AUT-04 | Just-in-time credentialing | GAP | None. Workers inherit host credentials (`gh` auth, token files). This is residual risk #1 — the PocketOS shape. |
| AUT-05 | Independent approval | GAP | Met part: one-way doors (`runtime/one-way-doors.json`) are human-only, never defaulted on timeout; `decisions.py` refuses a one-way line naming no human and refuses reclassification by rewording. Unmet: the approval is not authenticated — grant signatures are verified only when `.orca/human-grant-pubkey` is pinned, and this tree pins none, so today a person-shaped `--source human:<name>` is a name check, not proof a human approved. Pinning the key is a maintainer act. |
| AUT-06 | Fail-closed authorization and circuit breaking | VERIFIED | On the surfaces that grade merges (coordinator-run verify, CI verdict gates): `verify-gate.sh` exits 2 on a missing manifest (witnessed clean-machine); deny-hook polarity is deny-on-unparseable; spawn refuses without explicit opt-ins; floor guard blocks floor regressions; `tests/test_silent_skip_audit.py` audits every gate script for silent skips (#563). In a worker's own session the native hook is advisory by its own header — soundness there comes from the off-worker lanes, which is where this repo grades. |
| AUT-07 | Step-up verification | GAP | The human grant is the step-up for one-way doors in effect; there is no session-assurance-based re-verification. |
| AUT-08 | Just-in-time authority elevation | GAP | Grants are recorded with their human source; there is no expiring elevation object or agent-facing request path. |
| AUT-09 | Proof-of-possession credential binding | GAP | Nothing to bind: no broker issues credentials (see AUT-04). |

## Observe

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| OBS-01 | Agent-native telemetry | GAP | Manifests record commands, exits, durations, model, composition by reference. No cost/token accounting anywhere; effective runtime composition is declared, not observed. |
| OBS-02 | End-to-end correlation | GAP | A run's units correlate by run directory, task id, and SHA chain; target systems (GitHub) join by SHA/PR number only. No single cross-system trace identifier. |
| OBS-03 | Behaviour and drift monitoring | GAP | `watchdog.py` is liveness (slow/hung/wedged by time), not behaviour: no baselines over destinations, tool mix, or token burn. |
| OBS-04 | Unintended action detection | GAP | `diff_scope.py` classifies change surfaces fail-loud, CI runs gitleaks, build-blind review reads every lit diff. Nothing is tuned to "permitted but off-task" as a detection class. |
| OBS-05 | Intent-to-outcome evidence | VERIFIED | `runtime/scripts/run_report.py` binds a run only when the report, its own-directory manifest, and a re-hashed inventory at the named commit agree; per-unit manifests link contract → commands → review → `reviewed_sha == head_sha`. |
| OBS-06 | Evidence integrity, completeness and protection | GAP | The egress ledger is hash-chained, content-free, enforced by the deny-hook on `gh` writes, and anchored at run close (#561); signed verdict envelopes (`dispatch-sign.py`) cover verdict integrity. Remaining gap: run artifacts live in-repo with no automated retention/redaction lifecycle beyond `diagnose.md` rules. |

## Validate

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| VAL-01 | Agent-specific security testing | VERIFIED | `evals/injection-drills.json`, `scripts/eval.py --suite injection`, and `tests/test_injection_drills.py` (#560) continuously exercise adversarial prompt-injection payloads (instruction override, NFKC/zero-width/bidi evasion, authority claims, suppression requests, command execution, ChatML role-play markers, and forged banner breakouts) plus benign negative controls across all four untrusted surfaces (`issue`, `pr`, `ci`, `web`), alongside `tests/test_escape_probe.py` (#562). |
| VAL-02 | First-party agentic components testing | VERIFIED | Every mission/playbook/runtime change passes `scripts/validate.py` (budgets, identity, reference resolution) and the `tests/` suite in CI before merge. |
| VAL-03 | Agent-generated artifact testing | VERIFIED | A unit counts only when tests pass at its exact `head_sha` in a clean run and its negative control, executed by the verifier, goes red on revert/mutation. |
| VAL-04 | Agent outcome validation | GAP | Pre-merge outcome checks are strong (independent verifier re-derives from authoritative state). Post-merge business-outcome validation is mission-dependent, not systematic. |

## Respond

| ID | Control | Verdict | Evidence / gap |
|---|---|---|---|
| RES-01 | Immediate stop and authority revocation | GAP | A coordinator can stop workers and park units; there is no designed fleet-wide stop, and ambient credentials cannot be revoked per run. |
| RES-02 | Version and component quarantine | VERIFIED | `runtime/quarantine.json` + `runtime/scripts/quarantine_check.py` (#558) block any quarantined pack, mission, or playbook fail-closed across `scripts/validate.py`, `preflight.py --mission`, and `profile-gate.sh`, naming every transitively affected mission (`tests/test_quarantine.py`). |
| RES-03 | Impact scoping and evidence preservation | GAP | The evidence model makes scoping a query over manifests and egress receipts; there is no automated preservation snapshot procedure. |
| RES-04 | Safe failure and non-agent fallback | GAP | Unverified high-impact actions fail closed (AUT-06), but the fallback for essential work is "a human does it by hand" — undesigned and untested. |
| RES-05 | Agentic component rug-pull protection | VERIFIED | `runtime/scripts/pin_review.py` (#559, wired into `scripts/validate.py` and `tests/test_pin_review.py`) enforces a committed line-by-line rug-pull review under `docs/research/pin-reviews/<pack>-<sha>.md` for every upstream pack pin in `runtime/pins.json`, checking `Pack`, `From`, `To`, `Verdict: CLEAN`, `## Instruction diff`, and `## Permission & tool asks`. |

## Residual risks, ranked

1. **Ambient credentials (AUT-04).** A bypass-flagged worker holds whatever the host
   holds. The deny-hook and review gates reduce misuse; they do not reduce possession.
2. **Host-shell filesystem reach (CON-03).** `orca serve` v1.4.229 adds OS process/memory
   ceilings, and `tests/test_escape_probe.py` measures the `rw` deny-hook boundary, but
   until the ephemeral-sandbox lane has prelaunch placement binding, `rw` is not an OS mount namespace.
3. **No live credential revocation (RES-01).** Component quarantine (`RES-02`, #558) blocks
   bad packs/missions/playbooks fail-closed, but ambient host tokens still require manual rotation.

## What was adopted from this assessment

Filed as #557 (this assessment + the threat-model page) and implemented across #558 (quarantine
switch, `RES-02`), #559 (rug-pull pin review, `RES-05`), #560 (injection-drill evals, `VAL-01`),
#561 (egress wiring + anchoring, `AUT-01`/`OBS-06`), #562 (escape probe + hook-arming preflight,
`CON-03`), and #563 (silent-skip gate audit, `AUT-06`).

Deliberately **not** adopted as builds: a runtime authorization service, credential
broker, egress proxy with per-request decisions, and SIEM/GRC feeds. Those are
platform-layer (Orca/host) capabilities; the fleet names them as platform gaps rather
than simulating them in prompts. Also not adopted: the baseline's vocabulary over our
own — missions stay outcome-named, gates stay mechanical/taste/one-way; baseline IDs
appear only as a cited namespace, per that project's own ADR-0001.

## Re-assessment

Re-run this assessment when the baseline freezes at v1.0 (identifiers become stable),
when any row's enforcing artifact changes materially, or when `attest-it` is next run
as a fleet — at which point this file is the frozen catalog's first evidence draft, to
be re-derived, not trusted.

