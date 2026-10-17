# Runtime policy — threat model and the four boundaries

The fleet is a software factory: coordinators dispatch workers that read untrusted text,
hold real authority, and ship code. Security here does not rely on a worker obeying its
TASK; it relies on what the layers below the model make impossible or evident. This page
names the trust assumptions and the four boundaries (after Agent Baseline's *Secure
Software Factory* reference architecture, v1), states what enforces each today, and
grades the residue honestly. Per-control detail:
`docs/research/2026-10-14-agent-baseline-assessment.md`.

## Trust assumptions

| What | Trust | Why |
|---|---|---|
| A worker and anything it runs | Untrusted | It executes arbitrary code under a bypass flag |
| Everything a worker reads (issues, PRs, logs, scanned code, peer messages) | Untrusted | Any of it can carry injected instructions — data, never instructions (`sandbox-policy.md`) |
| Destinations a worker may reach | Untrusted | An approved service can itself be compromised |
| Checks run outside the worker with a trusted key (coordinator-run `verify.py`, CI verdict gates, dispatch signing) | Trusted | Their inputs do not originate with the graded worker; it must be hardened like a control plane |
| The same hooks run inside a worker's session (native Stop/TaskCompleted) | Advisory only | The worker controls their env and local refs there — defense in depth, never the soundness boundary (`verify-gate.sh` says so itself) |
| This repo's missions, playbooks, runtime policies | Trusted | They change only through reviewed PRs, never during a run |

A coordinator is also an agent: its plans are requests the gates check, never grants of
authority. One-way doors (`gate-classification.md`) stay human-only at every level of
autonomy the fleet runs.

## The four boundaries

### 1. Sandbox — where worker code runs

Today: an isolated git worktree per unit, spawn profiles (`ro`/`rw`/`danger`) with
fail-closed env opt-ins, the fail-closed PreToolUse deny-hook refusing the Never
shapes (`sandbox-policy.md`), and `orca serve` per-terminal OS resource ceilings at v1.4.229
(`ORCA_TERMINAL_PROCESS_CEILING`, `ORCA_TERMINAL_MEMORY_MAX`, `ORCA_TERMINAL_MEMORY_SWAP_MAX` via
Linux cgroup v2 / Windows Job objects, `terminal-host/containment/`). The `danger` ephemeral-VM lane
exists but is **refused** until a prelaunch placement binding proves the worker lands in the validated sandbox.

Residue: `rw` filesystem containment is a string-matched hook inside the worker's own harness, not
an OS mount namespace. It is now probed as one (`tests/test_escape_probe.py`): tool
writes, absolute-path redirects, and absolute `tee` destinations outside the worktree
are denied; relative redirects, `cp`/`mv`/`dd` and interpreter writes, credential
reads, network egress, and nested agent spawns are measured open and pinned
as known gaps. *Invariant we owe:* worker code runs
only where it cannot reach the host or another task, and that isolation is probed, not
asserted.

### 2. Network — what a worker can reach

Today: no egress proxy and no default-deny; a worker's network is the host's. Off-repo
writes are receipted first (`egress.py`, #368) — forensic, content-free, hash-chained.
Since #561 the deny-hook refuses an unreceipted `gh` write wherever the hook is wired
(worker sessions; coordinator sessions whose settings register it), and run close
anchors the chain head in committed records. Where the hook is not wired, receipting
remains coordinator discipline checked at close — receipts record sends; only the hook
gates them, and nobody should mistake the ledger for an exfiltration control.

Residue: exfiltration resistance rests on review of diffs and the deny-hook, not on a
network boundary. Destination allowlisting is a platform (Orca/host) capability; the
fleet names it a platform gap and does not simulate it in prompts.

### 3. Supply chain — which components and sources a worker may use

Today: upstream packs and the Orca runtime are pinned by commit with witness dates
(`runtime/pins.json`, re-witnessed by `pin-it`) and every pin advance requires a committed
rug-pull review (`docs/research/pin-reviews/<pack>-<sha>.md`) enforced by `pin_review.py` (#559);
`runtime/quarantine.json` blocks compromised packs/missions/playbooks fail-closed across
`validate.py`, `preflight.py --mission`, and the deny-hook (#558); one worker-pack router per
worker prevents composition clashes; and external text enters only through the `guard_text.py`
fence, continuously regression-tested against the adversarial prompt-injection drill suite
(`evals/injection-drills.json`, `scripts/eval.py --suite injection`, `tests/test_injection_drills.py`, #560).

Residue: upstream pack reviews rely on commit-pinned static inspection rather than cryptographic
provenance attestations; inputs are fenced against instructions (`guard_text.py`) but not
automatically redacted for embedded credentials before the worker context. *Invariant we owe:*
everything a run is built from comes from pinned, reviewed sources the worker did not
choose.

### 4. Identity and access — who a worker acts for and what it may do

Today: the coordinator signs each unit's contract digest and class out-of-band
(ed25519, `dispatch-sign.py`) so a worker cannot substitute its own denominator or
downgrade its class; gates classify every decision mechanical/taste/one-way, one-way
being human-only and never defaulted on timeout; verification is independent and
SHA-bound (`evidence-manifest.md`).

Residue — the fleet's top risk: **workers hold ambient host credentials** (`gh` auth,
token files). Nothing issues short-lived, task-scoped credentials, so possession, not
misuse, is the exposure. Mitigations in force are the deny-hook, `ro` for report-only
work, `danger` off-host doctrine, and review before merge; the boundary itself awaits
platform credential brokering.

## Execution and observability invariants (as held)

- A worker starts only through `spawn_worker.sh`'s fail-closed opt-ins; a refused
  spawn is recorded, never retried silently weaker.
- A unit that leaves no evidence manifest does not count, whatever its narration says.
- Committed run records (ledger, manifests, verdicts) are checked for changes after the
  fact — hashes, `reviewed_sha`, and run-report re-derivation detect edits against
  authoritative state (pushed SHAs, clean-env reruns); committing alone does not put
  them beyond a host-level writer's reach. Verdict envelopes are signed when the
  dispatch pubkey is pinned.

## Response ladder (graded — stop is the last rung, not the first)

1. **Steer.** Denials carry their reason and the governed path (deny-hook reasons,
   watchdog nudge with a finish-or-report demand). A worker that ignores steers is
   itself a signal.
2. **Reduce.** Park the unit; re-dispatch narrower (`ro`, smaller slice) or stop-redispatch.
3. **Stop.** Kill the worker(s) through Orca; block new dispatches on the affected DAG.
4. **Revoke.** Rotate whatever credentials the run could have touched — manual today,
   because credentials are ambient (boundary 4).
5. **Quarantine.** Block the implicated component fleet-wide: a human adds it to
   `runtime/quarantine.json` — validation then refuses any routing through it and
   preflight refuses its dispatch (#558).

## Out of scope

Model-provider security, abuse by a legitimate maintainer, and the host OS itself.
Anything a memory store or upstream pack feeds a worker is untrusted input under
boundary 3, not an exception to it.
