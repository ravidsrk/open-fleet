# Playbook — clean-env-drive  (prove first-run behaviour where no prior state exists)

Recipe: Orca placement (`worker-start --worktree new-child --setup run`) for repo-level
clean, Orca per-workspace environment recipes for machine-level clean. Any mission phase whose
oracle is first-run, install, or permission-prompt behaviour runs through here — the CLEAN-ENV
tier. A pass on a developer machine that already has caches, logins, and global installs proves
nothing about a first run.

## Name the cleanliness tier, then earn it

Two tiers, declared per step (`FRESHNESS=`): REPO-CLEAN (a fresh child worktree, setup run
from zero — no carried `node_modules`, caches, or env files) and MACHINE-CLEAN (a disposable
runtime booted from a snapshot, per the workspace recipe). A step that needs MACHINE-CLEAN is
never "verified" REPO-CLEAN; the tier is recorded per step and never upgraded silently.

## Assert the absence before the presence

Before installing anything, assert the negatives the tier promises: no repo checkout outside
the fresh workspace, no dependency caches, no `.env` or secret files, no login sessions, no
global tool installs the setup did not put there. Paste the listing commands and their empty
output — an unasserted clean room is a hope, not a tier.

## Install from scratch, from the repo's own docs

Clone, install dependencies, build, run — following ONLY the repo's documented setup, in order.
Each step's exact command and exit code is pasted; a step the docs omit but the run needed is a
finding against the docs, not a silent improvisation. Permission prompts (keychain, device,
notification, filesystem) are observed and quoted, never clicked through to keep the run green.

## Nothing survives the step except the evidence

Ephemeral means ephemeral: trap failures so a crashed provision removes the paid resource it
created, and destroy or release the workspace at step end. What leaves the clean room is the
evidence bundle — transcript, artifact paths, the snapshot or worktree id — bound into the
manifest (evidence-manifest.md). Credentials used for the install are session-scoped and never
persisted into the image, the state file, or the report.

## Labelled evidence lines

```
ENV=<worktree id | recipe id + snapshot id>  FRESHNESS=<REPO-CLEAN | MACHINE-CLEAN>
SETUP=<exit codes in order>  ARTIFACT=<path>  (transcript / screenshot / recording)
STEP_OK <step-name>
```

An artifact with no `head_sha` in its name cannot bind to a manifest and does not count. A
re-verify after a fix boots a FRESH environment at the new `head_sha` — never a reused one.

## Completion

The tier was declared and its absences asserted with pasted output; every setup command ran
from the repo's own docs with its exit code recorded; every permission prompt was quoted; paid
resources created by a failed step were removed; every artifact filename carries the `head_sha`
it was captured at; a step the tier could not reach is PARKED with the tier named, never
marked green on a dirtier tier.
