---
name: offload-it
description: >-
  Orca-environment setup (where the fleet itself runs). Stand up a per-workspace environment recipe end to end: interview the human for connection
  mode, provider, agent, and git auth, scaffold the lifecycle scripts and state file, build the
  base snapshot and the agent-auth snapshot, wire the environmentRecipes entry, and loop the
  recipe doctor dry-run plus live provision self-test until both pass — paid checkpoints gated
  on explicit human OKs, the interactive agent login left to the human. The unit is one recipe.
  Use when "run this in the cloud", "set up a sandbox recipe", "per-workspace environment",
  "orca vm recipe doctor fails", "provision ephemeral dev environments". Not for placing one
  worker on an existing host (orchestration), proving app behaviour on a fresh box
  (field-test-it CLEAN-ENV), or re-pinning runtime doctrine (pin-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter) with vm recipe doctor. A
  provider account + CLI with a sandbox/VM plan, and the provider's own docs for its verbs. An
  agent CLI + account for the auth snapshot. git + gh. One worker playbook pack per worker
  (matt or addy) — never two routers in one worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one per-workspace environment recipe (environmentRecipes entry + lifecycle scripts + state)
  state_machine: interview → scaffold → base snapshot → agent-auth snapshot → wire → doctor → provision loop
  convergence: doctor reports no fail and no warn AND the provision loop enacts create→validate→destroy
  ordering: fixed phase order — the auth snapshot boots from the base; create boots from the authenticated image
  parking: OFFLOADED-WITH-PARKED — quota, auth, and interactive-login parks each name their checkpoint
  oracle: the provider's real provisioned environment plus the recipe doctor's verdict
---

# offload-it — a recipe that provisions, proven by provisioning

You are the **COORDINATOR** of a recipe stand-up run. "Give this repo a working Run-on option"
is a user-facing outcome whose proof is enactment, not review: the doctor is clear AND a live
provision ran create→validate→destroy end to end. The phases run in FIXED ORDER — the auth
snapshot boots from the base snapshot, and create boots from the authenticated image — and the
money and the login are the human's: each paid checkpoint proceeds only on an explicit OK, and
the interactive agent login runs in the human's own terminal. Composes `human-handoff` (paid
checkpoints and the interactive login are human grants with verify-complete observations),
`research-brief` (the provider's exact create/exec/snapshot/remove verbs are read from its own
docs before scaffolding), `acceptance-review` (build-blind review of the recipe PR); rides
`evidence-manifest` (each recipe carries its doctor transcript, snapshot ids, and provision
transcript), `dispatch-lifecycle` (the recipe is written on a unit worktree off BASE, never the
primary checkout), `reviewed-sha-freshness`, `ledger-contract`, `gate-classification` (paid steps
and the promotion are one-way doors), `sandbox-policy` (PROFILE=rw; secrets never land in
scripts, userData, state, or commits). Worker TASK pack: one of matt | addy — never co-mount.

DEFERRED READS, never at activation: liveness-resume.md on a stall or resume.

## Terminal outcomes

- **OFFLOADED** — the doctor is clear (no fail AND no warn) and the provision loop is green end
  to end; state holds the AUTHENTICATED snapshot id; destroy is implemented and tested; the recipe
  is merged to BASE with its promotion PR open (Run-on appears once the human merges it).
- **OFFLOADED-WITH-PARKED** (degraded) — ≥1 park, each naming its checkpoint: a provider quota or plan cap
  (with the upgrade or smaller-scope ask), an unauthenticated agent login (the human re-runs
  device-auth), or an interactive step the human has not run yet.

## Pipeline

```
BOOTSTRAP integration BASE ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mission offload-it --base <BASE> --fork-point <sha>
  --require-gitleaks; BASE ≠ default — dispatch-lifecycle.md) → INSPECT the repo for an existing entry, scripts, state,
  or setup notes — a working recipe goes straight to the doctor loop, never a rebuild.
→ INTERVIEW, settled FIRST and confirmed back, never picked by the fleet: connection mode
  (Orca-server vs SSH — it changes the create output and half the templates), provider plus
  scope/project/region/plan, agent CLI plus account, git token source. Load `orca skills get
  orca-per-workspace-env` plus the matching `--references` (`provider-vercel`, `ssh-host`,
  `docker-ssh`, `windows-scripts`, `failure-modes`).
→ PREREQUISITES: provider CLI installed and authed, caps recorded (a 45-minute sandbox cap
  limits the base build AND the per-workspace runtime); each item marked verified or asserted.
→ SCAFFOLD scripts + state under scripts/orca-vm/ on the unit's worktree off BASE, executable, stdout
  reserved for the final JSON object; every script resolves values env → state → fallback.
→ BASE-SNAPSHOT [CHECKPOINT: explicit OK — paid and slow]: build headless main only, clone via
  a GIT_ASKPASS helper with escaped `\$1`/`\$GH_TOKEN` under `set -u` (rm'd after), trap errors
  so a crash removes the half-built environment, snapshot the STOPPED machine, parse the id into
  state. Never snapshot a machine where the runtime already ran — shared pairing identity; delete
  the verified user-data dir (`ORCA_USER_DATA_PATH` / `~/.config/orca`) first.
→ AGENT-AUTH [CHECKPOINT: the human runs the device-auth login, then says so]: headless means
  device-auth flow only (plain login hangs on an unreachable loopback callback); verify by the
  status command's exit code + `ORCA_AGENT_LOGGED_IN` sentinel (provider `exec` may drop remote
  exit codes; never grep-for-logged-in); refuse to snapshot unauthenticated.
  [CHECKPOINT: explicit OK — the re-snapshot is paid, and the login words above do not cover
  it]: re-snapshot, overwrite snapshotId, record authSourceSnapshotId, remove the auth
  environment.
→ WIRE orca.yaml create/suspend/resume/destroy at the scripts, on the same worktree. The doctor and
  `--provision` work on any branch (`--repo-path <unit worktree>`); only the picker needs the primary.
→ DOCTOR dry-run: free and static. Clear means NO fail AND NO warn (`ok` alone proves nothing);
  resolve each warn or record why it is accepted before spending on provision.
→ PROVISION loop [CHECKPOINT: one OK covers the whole fix-and-rerun loop]: read the
  provisionTranscript, fix the script, re-run to ok. Confirm separately that destroy really
  tears down (destroy:none means hand-cleanup, recorded, human-accepted).
→ PR against BASE (the integrator opens it; gitleaks-scanned) → build-blind REVIEW (acceptance-review:
  no secret anywhere, destroy real) → LAND (the conductor merges to BASE, ancestry-verified)
→ PROMOTE [ONE-WAY]: open the BASE→default promotion PR and stop — the composer reads recipes from
  the PRIMARY checkout, so Run-on appears only after the human merges it; never commit to default.
→ optional WORKSPACE-TEST [CHECKPOINT, only if asked, after that merge]: create via the picker,
  verify sleep/wake/delete.
→ VERDICT: OFFLOADED, or OFFLOADED-WITH-PARKED with the checkpoint register.
```

## Convergence proof (definition of done)

Each recipe carries: a doctor result with zero fail and zero warn; a provision transcript with
ok:true across create→validate→destroy; state holding the AUTHENTICATED snapshotId plus the
authSourceSnapshotId it superseded; destroy enacted, not assumed; the PR merged to BASE,
ancestry-verified, at its reviewed SHA. Negative control (evidence-manifest §1, executed per §2):
revert the unit's orca.yaml recipe entry and the free doctor dry-run fails — the recipe id no longer
resolves. The verifier re-runs that FREE dry-run and re-derives the transcript's resource ids through
provider read-only verbs — it never re-provisions (a re-provision is a paid step, and paid steps are
the human's).

## Ledger + supervision

Header at T0 per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP` (SOURCE =
provider + recipe id; WIP = 1 — snapshots are serial and paid); rows per ledger-contract.md. One row per
recipe: `| task_id | recipe | INTERVIEW | SCAFFOLD | BASE_SNAP | AUTH_SNAP | WIRED | DOCTOR |
PROVISION | destroy_tested | PR_OPEN | REVIEWED | MERGED | WT_CLEAN | lighting | park | evidence |`.
Paid checkpoints, the interactive login, and the promotion PR are OPS-queue items with
verify-complete observations; stalls → liveness-resume.md WATCH.

## Anti-patterns

Picking a provider, region, plan, or scope for the human (asked, never invented). Plain agent
login on a headless box (device-auth or hang). Grep-for-logged-in (matches "not logged in").
Snapshotting post-runtime state (every workspace from that image shares one pairing identity).
Secrets in scripts, userData, state, comments, docs, or commits. Writing the recipe on the primary
checkout or committing it to default (it reaches default only through the promotion PR). `provisioned-root` without an
explicit ask (and then only direct SSH + schema 2). Treating `ok:true` with warns as clear.
Bind-mounting a host agent home into the runtime (sqlite state and host config break there).

## Related

`field-test-it` (its CLEAN-ENV tier DRIVES a fresh room; this mission BUILDS the recipe that
boots one), `pin-it` (re-witness doctrine against the binary; this mission stands up new
infrastructure), `clean-env-drive` (the tier protocol that consumes what this mission proves).

Bundled copy of `offload-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
