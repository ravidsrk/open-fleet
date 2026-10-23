---
name: field-test-it
description: >-
  Verify an app on a real device or emulator and fix what only hardware shows: pair a device
  session through Orca's emulator/device skills, capture a pre-change regression baseline,
  reproduce the defect on-device with captured artifacts, fix it, and re-verify the same flow on-
  device at the head SHA — with the negative control that reverting the fix reintroduces the on-
  device failure. The unit is one device-observed defect (or one device QA pass over a flow). Use
  when "test on a real device", "works on desktop, breaks on mobile", "emulator QA", "on-device
  bug", "verify on hardware", "a regression no desktop run reproduces", "physical device testing".
  Not for web perf budgets (speed-it), WCAG conformance (access-it), test-coverage gaps (prove-
  it), framework/dependency upgrades (modernize-it), or a PR verdict (review-it).
license: MIT
compatibility: >-
  HARD dependency: open-fleet RPI runtime (Orca, posix, adapter) plus the target the tier needs:
  the Orca emulator skills (orca-emulator for iOS simulators, orca-emulator-android for Android) or
  a paired physical device; a driven browser (BROWSER), orca computer (DESKTOP), or a workspace
  recipe (CLEAN-ENV). git + gh. The app's own build/run toolchain. A fix worker playbook pack (mattpocock,
  addyosmani, gstack) — one router per worker.
metadata:
  proof: doctrine-only
  autonomy: L4
  unit: one device-observed defect (or one device QA pass over a flow)
  state_machine: baseline on target → reproduce on target → fix → re-verify on target → on-target revert control
  convergence: every defect is re-verified ON the target at head_sha with an on-target revert control
  ordering: one ledgered target session per unit; a desktop pass never substitutes
  parking: FIELD-PROVEN-WITH-PARKED — a defect the reached tier cannot show names its tier
  oracle: the target itself — a ledgered device session (DEVICE / EMULATOR / BROWSER / DESKTOP / CLEAN-ENV tiers)
---

# field-test-it — proven on hardware, not on hope

You are the **COORDINATOR** of an on-device verification run. "This flow works on a real device,
and what broke there is fixed and re-proven there" is a user-facing outcome whose oracle is
the ledgered target session itself: behaviour observed through it, typed by its tier on the ladder below (DEVICE · EMULATOR · BROWSER · DESKTOP · CLEAN-ENV). Simulators and desktops lie by omission —
rendering, input, permissions, lifecycle, and performance differ — so the device session is the
authority, and every fix is re-verified against it. Composes `diagnose` (on-device repro is a
diagnosis with a hardware oracle), `browser-drive` (the BROWSER tier), `computer-drive` (the DESKTOP tier), `clean-env-drive` (the CLEAN-ENV tier), `human-handoff` (device and permission
grants), `remediate-finding` (fix each defect), `acceptance-review` (build-blind review),
`compound-learn` (hardware-only defects feed the retro); rides `evidence-manifest` (each fix carries the on-device repro + re-verify artifacts at `head_sha`; negative control = revert reintroduces the on-device failure),
`merge-serialization`, `reviewed-sha-freshness`, `dispatch-lifecycle`,
`ledger-contract`, `sandbox-policy` (`PROFILE=rw` fix workers; device installs are host-side
rw work on the coordinator's machine — there is no device "danger lane": an ephemeral VM cannot
pair a phone), `gate-classification` (pairing/permission grants and anything outside the paired
device set are one-way human items — a stranger's device is never touched),
`attention-budget`. Worker TASK pack: one of matt | addy | gstack — never co-mount.

DEFERRED READS: liveness-resume.md on a stall or resume.

## Terminal outcomes

- **FIELD-PROVEN** — every defect observed on-device is fixed and re-verified on-device at
  `head_sha`; the regression baseline is re-ledgered; every fix's revert-negative-control holds.
- **FIELD-PROVEN-WITH-PARKED** (degraded) — ≥1 defect needs something the session lacks (a specific physical
  device/OS, a storefront account, a human gesture grant) and is PARKED with the exact device +
  step it waits on. A defect verified only in a desktop browser is PARKED, not proven.

## Pipeline

```
PAIR: load the version-matched guides from the binary (`orca skills get orca-emulator`,
  `orca skills get orca-emulator-android`) and establish the session per them — Android: boot/attach
  an emulator or an adb-visible physical device (adb, accessibility tree, logcat are the command
  surface); iOS: the Simulator pane via the app's own xcodebuild/simctl build+install first — the
  emulator skill does not install apps, and PHYSICAL iOS devices are not a command surface of either
  skill (a flow that needs physical iOS is PARKED). Preconditions stated in the ledger: macOS+Xcode
  for iOS Simulator, Android SDK/adb for Android, the Orca emulator pane up. Record the session's
  oracle tier, frozen per defect, from the ladder `DEVICE | EMULATOR | BROWSER | DESKTOP |
  CLEAN-ENV`: DEVICE (== PHYSICAL — hardware radios, thermal, real sensors) → EMULATOR
  (rendering/input/lifecycle, simulated sensors) → BROWSER (a web surface driven through
  `browser-drive`, its engine named and its evidence lines labelled) → DESKTOP (an OS/window-level
  surface driven through `computer-drive`, where every action carries a
  VERIFIED/UNVERIFIED result and an UNVERIFIED action is NEVER reported as success — if it could
  have sent, submitted, bought, or deleted something, the effect is unproven) → CLEAN-ENV (a
  disposable sandbox (`clean-env-drive`) proving first-run, install, and permission-prompt
  behaviour on a machine with no prior state). A defect class that only exists a tier up can
  never be proven a tier down; those are parked or paired, never "verified" on the weaker tier,
  and a tier is never upgraded silently.
→ BOOTSTRAP integration BASE ("$OPEN_FLEET_ROOT/runtime/scripts/preflight.py" --mission field-test-it --base <BASE> --fork-point <sha>;
  BASE ≠ default — dispatch-lifecycle.md). Fixes land on BASE, never the default branch.
→ BASELINE: capture the pre-change regression snapshot — the target flows driven on-device at the
  BASE head, screenshots/logs ledgered.
→ REPRODUCE (per defect): the reported or discovered failure observed on-device, artifact captured
  (screen recording / accessibility tree / logs). A defect that will not reproduce on-device is
  documented as attempted and does not enter the fix set — it is not silently closed either (PARK
  with the reproduction gap named).
→ FIX (rw workers, remediate-finding): one defect per unit; the fix never claims done from a
  desktop run.
→ build-blind REVIEW (acceptance-review) → LAND (merge-serialization).
→ RE-VERIFY: the same flow driven on-device at the unit's head SHA is GREEN, and the negative
  control holds: reverting the fix reintroduces the on-device failure (re-run the captured repro).
→ SNAPSHOT-LEDGER: the post-change on-device baseline is recorded for the next run.
→ VERDICT: FIELD-PROVEN, or FIELD-PROVEN-WITH-PARKED with the device/step register.
```

## Convergence proof (definition of done)

Every device-observed defect in the run's set is accounted for: repro artifact + fix + on-device
re-verify GREEN at `head_sha` + revert-to-red negative control, all ledgered with the capability
tier they were observed under — or PARKED with the exact device and step it waits on. The
regression baseline before and after is recorded. The verifier REPLAYS the recorded artifacts at
the merged SHA (the archived on-device repro re-driven expecting GREEN, plus a spot-check of the
archived revert-RED receipt) — it never re-applies an already-landed fix (evidence-manifest §2) —
AND, on a ≥10% sample per §3's mutation-unit floor, a fresh worker reverts the fix on a throwaway
branch and re-drives the on-device flow expecting RED (landed BASE is never modified). A green
desktop run is never accepted as device evidence; a
defect that only reproduced once is marked flaky and re-driven, not closed.

## Ledger + supervision

Ledger header at T0 (`ledger-contract.md`) with `WIP: builders=<n> reviewers=<n>` sized to
`attention-budget.md`. Header per liveness-resume.md: `RUN · COORDINATOR · BASE · FORK_POINT · T0 · SOURCE · WIP`
(`-` if N/A; SOURCE = the defect set + device/capability tier). One row per defect (canonical flags
per ledger-contract.md): `| task_id | defect | REPRO | BUILD_DONE | PR_OPEN | BOT | REVIEWED | MERGED | DEVICE_VERIFIED | WT_CLEAN | lighting | park | evidence |` — REPRO = the on-device
artifact captured pre-fix; DEVICE_VERIFIED = the fix re-verified on-device with artifacts; NC result
lives in `evidence`. Device sessions are serial by nature —
one active device lane per physical device; emulators scale within attention-budget. Stalls →
`liveness-resume.md` WATCH; device death (unpaired, battery, OS update) → RESUME re-pairs and
re-derives from the baseline ledger, never from a worker's narration.

## Anti-patterns

Accepting an emulator-tier pass as proof for a hardware-only defect class (sensors, thermal,
radios) — the oracle tier is recorded per defect and never upgraded silently. Accepting a
desktop/simulator pass as device proof when the run targeted hardware (and the reverse
— pairing a physical device when the mission's surface was an emulator flow). Closing a defect
from a fix that "should work" without the on-device re-verify. Skipping the revert negative
control because re-pairing is tedious (that is the only proof the fix caused the green). Treating
a one-time repro as a fix target without a flake note. Installing builds on devices outside the
paired set (sandbox-policy danger lane). Letting the baseline go unledgered so the next run starts
from memory.

## Related

`speed-it` (web perf budgets — its oracle is measurement, not hardware), `access-it` (WCAG
conformance on a rendered surface), `prove-it` (test-coverage gaps — its oracle is the suite),
`root-cause` (diagnosis without fix authority — field-test-it's REPRODUCE borrows its discipline
and adds the device oracle), `clean-sweep` (a findings backlog; device-observed defects can feed
one, but the device loop is this mission).

Bundled copy of `field-test-it`: every protocol named above is vendored in [`references/`](references/README.md), not two directories up.
