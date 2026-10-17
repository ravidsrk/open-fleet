# Comprehensive Visual Review of All 97 Repository Images

**Date:** 2026-10-17  
**Scope:** 100% visual inspection of all **97 raster assets** (`assets/*.jpg`, `assets/diagrams/*.jpg`, `assets/diagrams/missions/*.jpg`) compared against their canonical generator specifications in [`assets/diagrams/generator/specs.py`](../../assets/diagrams/generator/specs.py), [`assets/diagrams/generator/specs_new.py`](../../assets/diagrams/generator/specs_new.py), [`assets/diagrams/generator/specs_missions.py`](../../assets/diagrams/generator/specs_missions.py), and [`assets/diagrams/generator/specs_light.py`](../../assets/diagrams/generator/specs_light.py).

---

## Executive Summary (Post-Remediation)

| Category | Total Images | Dark / Light Pairs | 100% Clean & Parity-Matched | Minor Template Variations | Open Defects / Parity Drift |
|---|---:|---:|---:|---:|---:|
| **Hero & Social Banners** (`assets/*.jpg`) | 3 | 1 pair + 1 social | **3** | 0 | **0** |
| **Architecture & Concept Diagrams** (`assets/diagrams/*.jpg`) | 50 | 25 pairs | **50** (25 pairs) | 0 | **0** |
| **Mission Contract Cards** (`assets/diagrams/missions/*.jpg`) | 44 | 22 pairs | **8** (4 pairs) | 36 (18 pairs) | **0** (zero typos) |
| **Total** | **97** | **48 pairs + 1** | **61** | **36** | **0** |

---

## Remediated Findings (All 17 Actionable Images Fixed & Verified)

### P1 — Spelling & Character Corruptions (2 Images — FIXED)

1. **[`assets/diagrams/mission-map-light.jpg`](../../assets/diagrams/mission-map-light.jpg) — FIXED**
   - **Defect 1 (under `clean-sweep`):** Fixed `drain the backiog` → **`drain the backlog`**.
   - **Defect 2 (under `prove-it`):** Fixed `close the test tap` → **`close the test gap`**.
   - **Defect 3 (under `offload-it`):** Fixed `resipe, proven by provisioning` → **`recipe, proven by provisioning`**.

2. **[`assets/diagrams/tracker-enumeration.jpg`](../../assets/diagrams/tracker-enumeration.jpg) — FIXED**
   - **Defect (Stage 2 header):** Fixed **`TO TWIN-QUERY`** (capital letter `O`) → **`T0 TWIN-QUERY`** (slashed zero `0`), matching [`tracker-enumeration-light.jpg`](../../assets/diagrams/tracker-enumeration-light.jpg).

---

### P2 — Text Collisions & Omitted Captions in Architecture Diagrams (8 Images / 4 Pairs — FIXED)

1. **[`assets/diagrams/install-stack.jpg`](../../assets/diagrams/install-stack.jpg) & [`assets/diagrams/install-stack-light.jpg`](../../assets/diagrams/install-stack-light.jpg) — FIXED**
   - **Resolution:** Separated the 3-line caption (`zero-dependency fallback — the safety net stays OFF / paste the settings snippet`) from the amber `[wire the gate]` pill badge in Card 1 with a clean 14px horizontal gap.

2. **[`assets/diagrams/first-run.jpg`](../../assets/diagrams/first-run.jpg) & [`assets/diagrams/first-run-light.jpg`](../../assets/diagrams/first-run-light.jpg) — FIXED**
   - **Resolution:** Placed the green checkmark cleanly above the `[VERIFIED]` stamp inside the `evidence manifest — SHA-bound` document icon so every letter of `VERIFIED` is unobstructed, and removed the extra vertical double-headed arrows between the top and bottom worker rows.

3. **[`assets/diagrams/sandbox-profiles.jpg`](../../assets/diagrams/sandbox-profiles.jpg) & [`assets/diagrams/sandbox-profiles-light.jpg`](../../assets/diagrams/sandbox-profiles-light.jpg) — FIXED**
   - **Resolution:** Added the full two-line caption beneath the red-outlined `danger` vessel (`bypass approvals – opt-in flag required –` / `exploit PoCs, destructive tests.`) above `disposable per-workspace sandbox – never your machine.`.

4. **[`assets/diagrams/liveness-resume.jpg`](../../assets/diagrams/liveness-resume.jpg) & [`assets/diagrams/liveness-resume-light.jpg`](../../assets/diagrams/liveness-resume-light.jpg) — FIXED**
   - **Resolution:** Consolidated and completed the stalled-worker caption beneath the red-X terminal in the `WATCH` band to `worker – no heartbeat` / `past the window`.

---

### P3 — Dark vs. Light Mode Parity & Style Cleanups (7 Images — FIXED)

1. **[`assets/diagrams/proof-ladder.jpg`](../../assets/diagrams/proof-ladder.jpg) — FIXED**
   - **Resolution:** Recolored the right-hand callout box border (`the live state is the archive`) from blue (`#4C8DFF`) to amber (`#FFB84C`) to match [`proof-ladder-light.jpg`](../../assets/diagrams/proof-ladder-light.jpg) and `specs_new.py`.

2. **[`assets/diagrams/artifacts-map-light.jpg`](../../assets/diagrams/artifacts-map-light.jpg) — FIXED**
   - **Resolution:** Recolored the arrow between `merged into BASE` and `the promotion PR, BASE → default` to light-mode amber (`#C77700`) to match [`artifacts-map.jpg`](../../assets/diagrams/artifacts-map.jpg).

3. **[`assets/diagrams/attention-budget-light.jpg`](../../assets/diagrams/attention-budget-light.jpg) — FIXED**
   - **Resolution:** Transferred the dual blue+amber inner border on `WIP ≤ 3 builders` and the amber human-bottleneck icon (`#C77700`) from [`attention-budget.jpg`](../../assets/diagrams/attention-budget.jpg).

4. **[`assets/diagrams/verify-gate-light.jpg`](../../assets/diagrams/verify-gate-light.jpg) — FIXED**
   - **Resolution:** Replaced `·` with `+` in `contract source + digest` beneath Box 1 to match [`verify-gate.jpg`](../../assets/diagrams/verify-gate.jpg).

5. **[`assets/diagrams/gates-terminal.jpg`](../../assets/diagrams/gates-terminal.jpg) & [`assets/diagrams/gates-terminal-light.jpg`](../../assets/diagrams/gates-terminal-light.jpg) — FIXED**
   - **Resolution:** Removed the stray green/red underline bars beneath `default PR`, `stops`, and `merge it` inside the `PROMOTION` card.

6. **[`assets/diagrams/missions/ship-it-light.jpg`](../../assets/diagrams/missions/ship-it-light.jpg) — FIXED**
   - **Resolution:** Recolored the `RELEASED` hexagon and the 3-line artifact summary in `YOU GET BACK` to muted slate-grey (`#4F5E78`) to match [`ship-it.jpg`](../../assets/diagrams/missions/ship-it.jpg).

---

## Detailed Image-by-Image Catalog (All 97 Assets)

### Part 1: Hero & Social Banners (3 Images)

| # | Asset | Resolution | Status | Detailed Visual Notes |
|---:|---|---:|---|---|
| 1 | [`assets/hero-dark.jpg`](../../assets/hero-dark.jpg) | `2000×848` | **PASS** | Deep navy `#0B1220`, crisp orca pod surfacing across electric-blue waterline, constellation graph on right, exact typography: `orca-fleet`, `Give a mission a goal. Come back to an evidence-verified end state.`, `Autonomous fleets for the Orca runtime`. |
| 2 | [`assets/hero-light.jpg`](../../assets/hero-light.jpg) | `2000×848` | **PASS** | Cool ice-white `#F6F9FF` background, navy orca pod with white markings, dark ink `#0B1220` headline, deep blue `#09357A` subhead. 100% layout and text parity with `hero-dark.jpg`. |
| 3 | [`assets/social-preview.jpg`](../../assets/social-preview.jpg) | `2560×1280` | **PASS** | 2:1 OpenGraph card, identical typography and composition to `hero-dark.jpg` with generous 80px safe margin around all text. |

---

### Part 2: Architecture & Concept Diagrams (50 Images / 25 Pairs)

All 50 diagrams are `1600×900` (16:9).

| # | Diagram Pair (`dark` / `light`) | Status | Detailed Visual Audit (Dark & Light) |
|---:|---|---|---|
| 4–5 | [`artifacts-map.jpg`](../../assets/diagrams/artifacts-map.jpg) / [`-light.jpg`](../../assets/diagrams/artifacts-map-light.jpg) | **PASS** | Tree on left (`/tmp/orca-run-*/` and `docs/decisions/`) and 3 git branches on right (`worktree branch`, `BASE`, `default`) are crisp and 100% spelled correctly; amber promotion arrow matches across dark and light modes. |
| 6–7 | [`attention-budget.jpg`](../../assets/diagrams/attention-budget.jpg) / [`-light.jpg`](../../assets/diagrams/attention-budget-light.jpg) | **PASS** | Contrast between sprawl (`spawning is cheap`) and bounded `WIP ≤ 3 builders` (`one human — the serial bottleneck`) is crisp; dual blue+amber `WIP ≤ 3 builders` border and amber human icon match across both modes. |
| 8–9 | [`decision-gates.jpg`](../../assets/diagrams/decision-gates.jpg) / [`-light.jpg`](../../assets/diagrams/decision-gates-light.jpg) | **PASS** | Three lanes (`MECHANICAL`, `TASTE`, `ONE-WAY DOOR`) with green `PROCEED` badges and amber `PAUSE — WAIT FOR YOU` badge, dashed vertical override arrow from `ONE-WAY DOOR`, and 3 autonomy pills at bottom. 100% faithful to `specs.py`. |
| 10–11 | [`evidence-protocol.jpg`](../../assets/diagrams/evidence-protocol.jpg) / [`-light.jpg`](../../assets/diagrams/evidence-protocol-light.jpg) | **PASS** | Left-to-right flow (`WORKER` → `EVIDENCE MANIFEST` → `INDEPENDENT VERIFIER`) with all 6 verification checks (`git merge-base --is-ancestor`, `clean-env test pass at head_sha`, `negative control fails on revert`, `intent packet + legal lighting`, `reviewed_sha == head_sha`, `deployed_rev == reviewed_rev`) and green `VERIFIED` / red `VOID` badges. |
| 12–13 | [`first-run.jpg`](../../assets/diagrams/first-run.jpg) / [`-light.jpg`](../../assets/diagrams/first-run-light.jpg) | **PASS** | Three-stage flow (`> ship this: add /healthz` → `THE FLEET – coordinator + workers, each in its own worktree` → `evidence manifest – SHA-bound`). Green checkmark sits cleanly above `[VERIFIED]` and worker grid has clean horizontal flow. |
| 14–15 | [`fleet-topology.jpg`](../../assets/diagrams/fleet-topology.jpg) / [`-light.jpg`](../../assets/diagrams/fleet-topology-light.jpg) | **PASS** | `COORDINATOR` at top with `WIP ≤ 3 builders`, fan-out to `WORKER 1 · worktree A`, `WORKER 2 · worktree B`, `WORKER 3 · worktree C`, converging into `MERGE TRAIN` → `BASE` → amber `HUMAN GATE` → `DEFAULT BRANCH`. 100% faithful to `specs.py`. |
| 16–17 | [`gates-terminal.jpg`](../../assets/diagrams/gates-terminal.jpg) / [`-light.jpg`](../../assets/diagrams/gates-terminal-light.jpg) | **PASS** | `ONE-WAY` freeze grill prompt on left + `TASTE` and `PROMOTION` cards on right (`default PR`, `stops`, `merge it` clean without underlines). |
| 18–19 | [`install-stack.jpg`](../../assets/diagrams/install-stack.jpg) / [`-light.jpg`](../../assets/diagrams/install-stack-light.jpg) | **PASS** | Three stacked option cards (`1 · symlink into ~/.claude/skills`, `2 · ./scripts/install.sh`, `3 · claude plugin install orca-fleet`) with clean separation before `[wire the gate]`. |
| 20–21 | [`liveness-resume.jpg`](../../assets/diagrams/liveness-resume.jpg) / [`-light.jpg`](../../assets/diagrams/liveness-resume-light.jpg) | **PASS** | `WATCH` band (`worker – no heartbeat / past the window` → `respawn in a FRESH terminal`) and `RESUME` band (`dead coordinator` + `ledger` → `new coordinator` → `reconnect, scoped to its own run`). |
| 22–23 | [`merge-train.jpg`](../../assets/diagrams/merge-train.jpg) / [`-light.jpg`](../../assets/diagrams/merge-train-light.jpg) | **PASS** | Three worktree branches entering `SERIAL MERGE QUEUE (1 → 2 → 3)` with `rebase onto BASE · run suite · fast-forward` into `BASE`, plus amber `HUMAN GATE — promotion PR` to `DEFAULT`. 100% faithful to `specs.py`. |
| 24–25 | [`mission-chaining.jpg`](../../assets/diagrams/mission-chaining.jpg) / [`-light.jpg`](../../assets/diagrams/mission-chaining-light.jpg) | **PASS** | `map-it` → `ship-it` → `harden-it` chain with green `MAPPED` / `BUILT` handoffs, downward amber `*-WITH-PARKED` arrows into red `CHAIN STOPS — human decides before next mission`, and green `DEPLOYED_AND_VERIFIED` terminal. |
| 26–27 | [`mission-handoffs.jpg`](../../assets/diagrams/mission-handoffs.jpg) / [`-light.jpg`](../../assets/diagrams/mission-handoffs-light.jpg) | **PASS** | Directed handoff graph across all 10 participating missions (`map-it`, `root-cause`, `prove-it`, `attest-it`, `clean-sweep`, `ship-it`, `modernize-it`, `migrate-it`, `harden-it`, `review-it`) with exact edge labels (`frozen DAG`, `fix brief`, `surfaced bug`, `remediate gaps`, `build findings`, `stateful migration`, `risky diff`, `GO / NO-GO`). |
| 28–29 | [`mission-identity.jpg`](../../assets/diagrams/mission-identity.jpg) / [`-light.jpg`](../../assets/diagrams/mission-identity-light.jpg) | **PASS** | 6 identity cards (`1 · UNIT`, `2 · STATE MACHINE`, `3 · CONVERGENCE`, `4 · ORDERING`, `5 · PARKING`, `6 · ORACLE`) feeding `STEM + SYNONYM COMPARISON (validate.py #288)` with green `≥ 1 POINT DIVERGES — TWO MISSIONS` and red `ALL 6 MATCH OR PARAPHRASE — BUILD FAILS`. |
| 30–31 | [`mission-map.jpg`](../../assets/diagrams/mission-map.jpg) / [`-light.jpg`](../../assets/diagrams/mission-map-light.jpg) | **PASS** | 22-mission decision tree (`WHICH MISSION DO I WANT?`). Both dark and light modes have 100% accurate spelling (`drain the backlog`, `close the test gap`, `recipe, proven by provisioning`). |
| 32–33 | [`negative-control.jpg`](../../assets/diagrams/negative-control.jpg) / [`-light.jpg`](../../assets/diagrams/negative-control-light.jpg) | **PASS** | Two-panel comparison (`1 · AT HEAD_SHA — THE FIX IS PRESENT` → `TEST PASSES`, `2 · REVERT OR MUTATE THE FIX` → `TEST FAILS` → green `PROOF HOLDS` vs `TEST STILL PASSES` → red `VOID — TAUTOLOGY`). 100% faithful to `specs_new.py`. |
| 34–35 | [`one-router-per-worker.jpg`](../../assets/diagrams/one-router-per-worker.jpg) / [`-light.jpg`](../../assets/diagrams/one-router-per-worker-light.jpg) | **PASS** | Left panel (`ALLOWED — CROSS-PACK AT MISSION LEVEL` with green `CLEAN`) vs right panel (`FORBIDDEN — TWO ROUTERS IN ONE WORKER` with red `CONFLICT`). 100% faithful to `specs.py`. |
| 36–37 | [`proof-ladder.jpg`](../../assets/diagrams/proof-ladder.jpg) / [`-light.jpg`](../../assets/diagrams/proof-ladder-light.jpg) | **PASS** | Three-rung ladder (`doctrine-only` → `self-run` → `external-run`) + right archive callout with amber border matching across dark and light modes. |
| 38–39 | [`reviewed-sha-freshness.jpg`](../../assets/diagrams/reviewed-sha-freshness.jpg) / [`-light.jpg`](../../assets/diagrams/reviewed-sha-freshness-light.jpg) | **PASS** | Top lane (`CASE A — NO POST-REVIEW COMMITS` → green `FRESH — MERGE ALLOWED`) vs bottom lane (`CASE B — REBASE OR AMEND AFTER REVIEW` → `git diff-tree reviewed_sha head_sha` → green `TREE UNCHANGED — VERDICT STANDS` or red `VOID — RE-REVIEW REQUIRED`). |
| 40–41 | [`run-timeline.jpg`](../../assets/diagrams/run-timeline.jpg) / [`-light.jpg`](../../assets/diagrams/run-timeline-light.jpg) | **PASS** | 6-stage horizontal lifecycle (`1 · INTENT` → `2 · PREFLIGHT` → `3 · DISPATCH` → `4 · VERIFY` → `5 · MERGE TRAIN` → `6 · PROMOTE`) with green `SHIPPED` badge and feedback loops (`re-dispatch`, `next slice`). |
| 42–43 | [`sandbox-profiles.jpg`](../../assets/diagrams/sandbox-profiles.jpg) / [`-light.jpg`](../../assets/diagrams/sandbox-profiles-light.jpg) | **PASS** | Three profile vessels (`ro`, `rw`, `danger`) with complete captions (`bypass approvals – opt-in flag required – / exploit PoCs, destructive tests.`) over `disposable per-workspace sandbox – never your machine.`. |
| 44–45 | [`threat-boundaries.jpg`](../../assets/diagrams/threat-boundaries.jpg) / [`-light.jpg`](../../assets/diagrams/threat-boundaries-light.jpg) | **PASS** | Left 2×2 grid (`1 SANDBOX`, `2 NETWORK`, `3 SUPPLY CHAIN`, `4 IDENTITY & ACCESS`) and right 5-rung `RESPONSE LADDER` (`1 STEER` → `2 REDUCE` → `3 STOP` → `4 REVOKE` → `5 QUARANTINE`). 100% faithful to `specs_new.py`. |
| 46–47 | [`three-layers.jpg`](../../assets/diagrams/three-layers.jpg) / [`-light.jpg`](../../assets/diagrams/three-layers-light.jpg) | **PASS** | Top-to-bottom architecture stack (`MISSIONS · skills/<name>/SKILL.md` → `PLAYBOOKS · playbooks/<name>.md` → `RUNTIME · runtime/*.md + runtime/scripts/`) with side callout `scripts/validate.py enforces layer boundaries`. |
| 48–49 | [`tracker-enumeration.jpg`](../../assets/diagrams/tracker-enumeration.jpg) / [`-light.jpg`](../../assets/diagrams/tracker-enumeration-light.jpg) | **PASS** | 4-stage pipeline (`HOSTED TRACKERS` → `T0 TWIN-QUERY` → `GUARD_TEXT.PY TRUST FENCE` → `SINGLE-ATTEMPT CLOSURE`) with slashed zero `T0` in both dark and light modes. |
| 50–51 | [`verify-gate.jpg`](../../assets/diagrams/verify-gate.jpg) / [`-light.jpg`](../../assets/diagrams/verify-gate-light.jpg) | **PASS** | 3-step `worker_done` interception (`THE COORDINATOR SETS THE GATE ENV` → `STOP / TASKCOMPLETED HOOK FIRES VERIFY-GATE.SH` → `VERIFY.PY RE-DERIVES` → green `EXIT 0 — ALLOW` / red `EXIT 2 — BLOCK, WITH FEEDBACK`) with `contract source + digest` matching in both modes. |
| 52–53 | [`you-say.jpg`](../../assets/diagrams/you-say.jpg) / [`-light.jpg`](../../assets/diagrams/you-say-light.jpg) | **PASS** | 6 speech-bubble prompts (`"build and ship this"` → `ship-it`, `"drain the backlog"` → `clean-sweep`, `"why is this happening"` → `root-cause`, `"harden this"` → `harden-it`, `"kill the flaky tests"` → `deflake-it`, `"review this PR"` → `review-it`). 100% faithful to `specs_new.py`. |

---

### Part 3: Mission Contract Cards (44 Images / 22 Pairs)

All 44 mission contract cards are `1600×900` (16:9) and have **100% accurate spelling** against `specs_missions.py`. Four pairs (`deflake-it`, `field-test-it`, `harden-it`, `migrate-it`) follow the strict template with minimal or zero drift; the remaining 18 pairs exhibit minor template variations (such as inner hexagon icons, 2-line titles, or highlighted phase names) cataloged below.

| # | Mission Card Pair (`dark` / `light`) | Status | Detailed Visual Audit vs. `specs_missions.py` |
|---:|---|---|---|
| 54–55 | [`absorb-it.jpg`](../../assets/diagrams/missions/absorb-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/absorb-it-light.jpg) | **STYLE** | Spelling 100% accurate. **Style notes:** Outcome placed on a 2nd line below `absorb-it` (no em-dash); panel headers rendered inside solid blue corner tabs; `ABSORBED` and `ABSORBED-WITH-PARKED` badges include a left double-chevron icon (`«`). |
| 56–57 | [`access-it.jpg`](../../assets/diagrams/missions/access-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/access-it-light.jpg) | **STYLE** | Spelling 100% accurate. **Style notes:** Outcome placed on a 2nd line below `access-it` (no em-dash); `CONFORMANT` and `CONFORMANT-WITH-MANUAL-PARKED` hexagons contain a small inner hexagon icon. |
| 58–59 | [`attest-it.jpg`](../../assets/diagrams/missions/attest-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/attest-it-light.jpg) | **STYLE** | Single-line title, 100% accurate spelling. **Style note:** `CONFORMANT` and `CONFORMANT-WITH-GAPS` hexagons contain a small inner hexagon icon. |
| 60–61 | [`clean-sweep.jpg`](../../assets/diagrams/missions/clean-sweep.jpg) / [`-light.jpg`](../../assets/diagrams/missions/clean-sweep-light.jpg) | **STYLE** | Single-line title, 100% accurate spelling. **Style note:** `DRY` and `DRY-WITH-PARKED` are drawn as rounded pill badges with an inner hexagon icon rather than outer hexagons. |
| 62–63 | [`deflake-it.jpg`](../../assets/diagrams/missions/deflake-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/deflake-it-light.jpg) | **PASS** | Single-line title, clean single hexagons (`STABLE` green, `STABLE-WITH-QUARANTINE` amber), symmetric 2×2 grid, exact phase strip. 100% faithful to `specs_missions.py`. |
| 64–65 | [`document-it.jpg`](../../assets/diagrams/missions/document-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/document-it-light.jpg) | **STYLE** | Clean single hexagons (`DOCUMENTED`, `DOCUMENTED-WITH-PARKED`), 100% accurate spelling. **Style notes:** Outcome on 2nd line (no em-dash); asymmetric bottom row (`YOU GET BACK` is taller than `IT STOPS AT`); artifact list uses primary white/black text instead of muted grey-blue. |
| 66–67 | [`field-test-it.jpg`](../../assets/diagrams/missions/field-test-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/field-test-it-light.jpg) | **STYLE** | Clean single hexagons (`FIELD-PROVEN`, `FIELD-PROVEN-WITH-PARKED`), symmetric 2×2 grid, 100% accurate spelling. **Style note:** Outcome on 2nd line (no em-dash). |
| 68–69 | [`floor-it.jpg`](../../assets/diagrams/missions/floor-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/floor-it-light.jpg) | **STYLE** | Single-line title, clean single hexagons (`FLOORED`, `FLOORED-WITH-PARKED`), 100% accurate spelling. **Style note:** In `IT STOPS AT`, colors `violations` red and `never on BASE` green. |
| 70–71 | [`harden-it.jpg`](../../assets/diagrams/missions/harden-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/harden-it-light.jpg) | **STYLE** | Single-line title, symmetric 2×2 grid, 100% accurate spelling. **Style note:** `CLEAN` and `HARDENED-WITH-OPEN-ITEMS` hexagons contain a small inner hexagon icon. |
| 72–73 | [`map-it.jpg`](../../assets/diagrams/missions/map-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/map-it-light.jpg) | **STYLE** | Single-line title, clean single hexagons (`MAPPED`, `MAPPED-WITH-BLOCKED`), 100% accurate spelling. **Style notes:** Places hexagons inline to the right of the `YOU GET BACK` header; renders the 3 artifact items on separate lines in primary white/black text without middle dots. |
| 74–75 | [`migrate-it.jpg`](../../assets/diagrams/missions/migrate-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/migrate-it-light.jpg) | **PASS** | Single-line title, clean three hexagons (`MIGRATED` green, `MIGRATED-WITH-PARKED` amber, `ABANDONED` grey), symmetric 2×2 grid, exact phase strip. 100% faithful to `specs_missions.py`. |
| 76–77 | [`modernize-it.jpg`](../../assets/diagrams/missions/modernize-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/modernize-it-light.jpg) | **STYLE** | Single-line title, 100% accurate spelling. **Style notes:** Omits em-dash after `modernize-it`; `CURRENT` and `CURRENT-WITH-PINNED` include inner hexagon icons (solid fill in light mode); artifact text in `YOU GET BACK` uses primary white/black type instead of muted grey-blue. |
| 78–79 | [`offload-it.jpg`](../../assets/diagrams/missions/offload-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/offload-it-light.jpg) | **STYLE** | Single-line title, 100% accurate spelling. **Style notes:** `OFFLOADED` and `OFFLOADED-WITH-PARKED` include inner hexagon icons; omits the second middle dot `·` before `an enacted provision transcript` at line wrap. |
| 80–81 | [`oncall-it.jpg`](../../assets/diagrams/missions/oncall-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/oncall-it-light.jpg) | **STYLE** | Clean single hexagons (`OPERABLE`, `OPERABLE-WITH-PARKED`), 100% accurate spelling. **Style notes:** Long title wraps onto 2 lines in primary white/black text; first 2 artifact lines in `YOU GET BACK` are rendered in primary white/black (and all 3 in light mode). |
| 82–83 | [`oss-contribute.jpg`](../../assets/diagrams/missions/oss-contribute.jpg) / [`-light.jpg`](../../assets/diagrams/missions/oss-contribute-light.jpg) | **STYLE** | Single-line title, symmetric 2×2 grid, 100% accurate spelling. **Style note:** `CONTRIBUTED` and `CONTRIBUTED-WITH-PARKED` include inner hexagon icons. |
| 84–85 | [`pin-it.jpg`](../../assets/diagrams/missions/pin-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/pin-it-light.jpg) | **STYLE** | Single-line title, symmetric 2×2 grid, 100% accurate spelling. **Style notes:** `PINNED` and `PINNED-WITH-PARKED` include inner hexagon icons (solid fill in light mode); `RE-WITNESS` is highlighted in primary white/black in the bottom phase strip. |
| 86–87 | [`prove-it.jpg`](../../assets/diagrams/missions/prove-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/prove-it-light.jpg) | **STYLE** | Single-line title, clean single hexagons (`COVERED`, `COVERED-WITH-PARKED`), 100% accurate spelling. **Style notes:** Panel headers sit in top-border cutouts in electric blue; full-width horizontal rule above phase strip with `MUTATION-AUDIT` highlighted. |
| 88–89 | [`reshape-it.jpg`](../../assets/diagrams/missions/reshape-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/reshape-it-light.jpg) | **STYLE** | Symmetric 2×2 grid, 100% accurate spelling. **Style notes:** Title wraps onto 2 lines in primary white/black text; `RESHAPED` and `RESHAPED-WITH-PARKED` include inner hexagon icons (solid fill in light mode). |
| 90–91 | [`review-it.jpg`](../../assets/diagrams/missions/review-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/review-it-light.jpg) | **STYLE** | Single-line title, clean hexagons (`GO` green, `NO-GO` red), 100% accurate spelling. **Style notes:** Inserts `or` between `GO` and `NO-GO` hexagons; renders first two lines of artifacts in primary white/black and only `reviewed_sha` in muted grey-blue. |
| 92–93 | [`root-cause.jpg`](../../assets/diagrams/missions/root-cause.jpg) / [`-light.jpg`](../../assets/diagrams/missions/root-cause-light.jpg) | **PASS** | Single-line title, clean three hexagons (`DIAGNOSED` green, `DIAGNOSED-WITH-HANDOFF` green, `INCONCLUSIVE` amber; solid fills in light mode), symmetric 2×2 grid. Minor highlight on `RED LOOP` inside a subtle pill container on the bottom phase strip. |
| 94–95 | [`ship-it.jpg`](../../assets/diagrams/missions/ship-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/ship-it-light.jpg) | **PASS** | Single-line title, clean four hexagons (`BUILT`, `PROMOTION_READY`, `RELEASED`, `DEPLOYED_AND_VERIFIED`), symmetric 2×2 grid, muted slate-grey artifact list matching across dark and light modes. |
| 96–97 | [`speed-it.jpg`](../../assets/diagrams/missions/speed-it.jpg) / [`-light.jpg`](../../assets/diagrams/missions/speed-it-light.jpg) | **STYLE** | Single-line title, symmetric 2×2 grid, 100% accurate spelling. **Style note:** `WITHIN-BUDGET` and `OPTIMIZED-WITH-PARKED` hexagons include inner hexagon icons. |
