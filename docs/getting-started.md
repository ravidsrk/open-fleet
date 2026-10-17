# Getting started with orca-fleet

[Documentation](README.md) · [Install](install.md) · [Prompt recipes](recipes.md)

Use this guide to run a mission on your project. It assumes you have used Claude Code before
but never run a multi-agent fleet. You will install the catalog, review an existing change,
then see how a bounded feature moves to a promotion PR. For editing this repository and running
its local checks, use [Development](development.md).

## Contents

- [Prerequisites](#prerequisites)
- [Install the catalog](#install-the-catalog)
- [Your first mission: a review-it dry run](#your-first-mission-a-review-it-dry-run)
- [Your second mission: ship-it end to end](#your-second-mission-ship-it-end-to-end)
- [What you will see while a fleet runs](#what-you-will-see-while-a-fleet-runs)
- [Where the evidence lands](#where-the-evidence-lands)
- [Your side of the human gates](#your-side-of-the-human-gates)
- [What a run costs](#what-a-run-costs)
- [Troubleshooting](#troubleshooting)

## Prerequisites

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/install-stack.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/install-stack-light.jpg">
    <img src="../assets/diagrams/install-stack-light.jpg" alt="The stack, bottom to top: the Orca app with orchestration enabled, the orca CLI, the orchestration and orca-cli skills, the orca-fleet missions, and the upstream packs, one per worker; three install paths: a symlink with the completion gate off until the settings snippet is wired, the Claude Code plugin with the gate on by construction, and the skills CLI, which severs playbook references and is not supported today" width="820">
  </picture>
</p>

Three hard requirements, without which no mission will start:

1. **The Orca app, the `orca` CLI, and Orca's two public skills, `orchestration` and
   `orca-cli`** (all shipped with Orca, not with this repo; on Linux outside an Orca terminal the
   CLI is `orca-ide`). Missions are coordinators for Orca fleets: they create worktrees, spawn
   worker terminals, dispatch tasks, and read `worker_done` messages (the message a worker sends
   when it claims a unit is finished) through Orca. Verify with:

   ```bash
   orca status --json
   ```

   With the app closed it answers `"runtime": {"state": "not_running", "reachable": false}`.
   Run `orca open`, wait until `runtime.state` reads `ready`, and a mission can start. The
   before-and-after transcript is
   [P0-r3-orca-status.txt](completion/evidence/P0-r3-orca-status.txt).

2. **`git` and `gh`**, authenticated. Fleets open PRs per unit of work and verify merges by
   ancestry; `gh auth status` must succeed. Repos on a tracker other than GitHub issues can use
   `orca linear` or `orca jira` where a mission supports it.

3. **Python 3.11 or newer** for the catalog gates (`scripts/validate.py`, `tests/`) and for the
   runtime scripts a fleet runs (`runtime/scripts/verify.py` and its neighbours). CI runs the
   suite on 3.11, 3.12 and 3.13 (3.10 compiles, but two tests depend on 3.11 interpreter
   behaviour, so it is not supported); stdlib only — no venv required.

Per-mission tooling on top of that — each mission declares its own in `SKILL.md` frontmatter:

| If you plan to run | Also install |
|---|---|
| any mission | `git` + `gh`, or a tracker reachable via `orca linear` / `orca jira` |
| harden-it | `gitleaks`, plus an ephemeral per-workspace sandbox for exploit PoCs |
| speed-it | a real measurement path: Lighthouse/DevTools access, or a load/profiler harness |
| modernize-it | the project's package manager; CI must be green at baseline |
| prove-it | a runnable suite plus a coverage tool it already supports |
| deflake-it | a runnable suite; CI history is read via `gh run list` |
| ship-it | your deploy tooling and a canary surface, if you want the states past `RELEASED` |
| pin-it | the installed Orca CLI itself (`orca skills get` is the re-witness oracle) |
| floor-it | the repo's own counters per dimension (coverage runner, scanner, harness, linter) and CI write access on BASE |
| reshape-it | the repo's mutation tooling (or the hand-mutant fallback) plus a runnable suite |
| field-test-it | an Orca emulator skill (`orca-emulator` / `orca-emulator-android`) or a paired device, plus the app's build toolchain |

This table is the single home of the per-mission list; the README links here rather than
repeating it.

## Install the catalog

Follow [Install](install.md#choose-an-install-path) for the path comparison and full procedure.
The minimal selected-mission setup below runs in the **orca-fleet clone**. Keep it available;
the links and completion hook resolve files inside it.

**Symlink (recommended while evaluating).** Some missions link `../../ARCHITECTURE.md` relative
to their own directory, and every mission resolves its playbooks by bare name against the repo
tree. A symlink preserves both; a copy severs them — this is the single most common
broken-install cause.

One thing the symlink path does **not** wire: the native completion gate. `hooks/hooks.json`
registers `verify-gate.sh` on `Stop` / `TaskCompleted` through `${CLAUDE_PLUGIN_ROOT}`, a path
that exists only under the plugin install below. On a symlinked mission nothing fires that hook
until you wire it yourself: the coordinator still runs `verify.py` where its playbooks say so,
but no hook blocks a turn on a failing manifest. The settings snippet that resolves the repo path
is in [docs/verify-gate.md](verify-gate.md); `sh hooks/print-settings-snippet.sh` prints it.

```bash
git clone https://github.com/ravidsrk/orca-fleet.git
cd orca-fleet
mkdir -p ~/.claude/skills
ln -s "$(pwd)/skills/ship-it"   ~/.claude/skills/ship-it
ln -s "$(pwd)/skills/review-it" ~/.claude/skills/review-it
```

**Plugin (whole catalog).** The manifest at `.claude-plugin/plugin.json` installs the entire
mission catalog at once; the relative references resolve inside the copied plugin directory:

```
/plugin marketplace add ravidsrk/orca-fleet
/plugin install orca-fleet@orca-fleet
```

Confirm the install by asking your agent "which missions are available?" — the
outcome-named skills should list; with the two symlinks above you get `ship-it` and `review-it`.
If a mission is visible but errors on start about missing playbooks, you copied instead of linking.

**Wiring the gate on a symlink install.** `sh hooks/print-settings-snippet.sh` prints a JSON
object with a `hooks` key — a `TaskCompleted` entry and a `Stop` entry, each running
`verify-gate.sh` from your clone by absolute path — plus a `_comment` key you can delete. Merge
the `hooks` entries into `~/.claude/settings.json`. The script's `--check` flag only confirms the
clone still holds the template and `verify-gate.sh`; it never reads your settings, so it prints
`ok` whether or not the hooks are installed. Confirm the wiring itself, then exercise the gate:

```bash
grep -c verify-gate.sh ~/.claude/settings.json                        # 2 — one per hook entry
ORCA_MANIFEST=/nonexistent.json sh runtime/scripts/verify-gate.sh --event stop; echo "exit $?"
```

The second line must end in `BLOCKING (fail-closed)` and `exit 2`: a named-but-missing manifest is
refused, which is the behavior a mis-wired gate would silently lack. The `Stop` hook fires on every
turn end, which is harmless: with no unit in progress (`ORCA_MANIFEST` unset) it allows the turn,
and it blocks only a turn that is mid-unit with a failing manifest
([docs/verify-gate.md](verify-gate.md#native-path--plugin-hooks-set-claude_plugin_root)).

## Your first mission: a review-it dry run

Before any run, read the README's
[Before you run a mission](../README.md#before-you-run-a-mission) section: it says what a
fleet does on your machine (permission-bypass workers, worktrees, PRs on your repository) and
where to run a first one.

Start with [`review-it`](missions/review-it.md): it evaluates an existing change without fixing
project code. After the install checks, open a **fresh coding-agent session in the target
repository**, identify a PR with a non-empty diff, and supply the issue or spec it implements.
Replace the values in this example and paste it into the agent prompt:

```text
review this PR: <PR URL>
Use <issue URL or spec path> as the acceptance criteria.
Return a SHA-bound GO/NO-GO verdict with findings grouped by review axis.
```

**How proven is it?** `review-it` reads `external-run`. Its binding run
([2026-10-13](runs/2026-10-13-review-it-linux.md)) reviewed a real PR on a repository other
than this catalog (stablyai/orca #28206) from Ubuntu via `orca-ide`: four read-only workers, a
NO-GO verdict bound to the reviewed SHA, every quote re-read, `verify.py` OK, every artifact
retained and re-hashable here. That proves the protocol ran end to end once, maintainer-driven,
on one PR. It does not prove the verdict is right for your PR, and it was run by the
maintainer, not an independent party (see [proof status](concepts.md#proof-status)).

What happens, in order:

1. The coordinator pins the fixed point — a SHA or PR with a non-empty diff — and identifies
   the spec source (the PR description, the linked issue, a spec file).
2. Read-only workers (`PROFILE=ro`) run the acceptance axes in parallel isolation: repo
   standards, spec fidelity, test adequacy. Risk lenses (security, performance, accessibility,
   data migration) dispatch only if the diff triggers them.
3. Findings that cannot quote the exact line that motivated them drop to an appendix — that one
   rule removes most of the false positives you have seen from single-agent reviews.
4. You get a GO / NO-GO verdict bound to the reviewed SHA. Any Critical or Required finding
   defaults the verdict to NO-GO. A later content-changing push needs a fresh review.

Check the result for the reviewed commit, all three acceptance axes, the reasons risk lenses
ran or were skipped, and the quoted evidence behind each finding. `GO` is the review's outcome;
the PR's checks, review requirements and merge decision still apply. The native worker profile
and completion hook have the [documented advisory boundary](verify-gate.md#trust-boundary).

The first thing the coordinator writes, before any dispatch, is the ledger header. This one is
real, from the run [Anatomy of a run](guides/anatomy-of-a-run.md) walks:

```
RUN: clean-sweep-chimely-20260715 · COORDINATOR: term_905ccdf2… + term_c5e4d798… ·
BASE: clean-sweep/integration · FORK_POINT: ce7891bf… · T0: 2026-07-15T17:40:00Z ·
SOURCE: tracker dodopayments/chimely open issues #34,35,36,37,38,39,55,56,58,61
(count=10, enumerated via gh api --paginate state=open)
```

A `review-it` header has the same shape with `BASE: -`, because a report-only mission has no
integration branch to merge into ([`runtime/liveness-resume.md`](../runtime/liveness-resume.md)).
Everything a crash-resume needs is on that line: which terminals own the run, which branch
integrates, and the exact denominator with how it was enumerated (`T0` is the moment it was
frozen).

Total cost: a few worker sessions, no writes, and you have now seen the coordinator/worker shape
without risking a single line of code.

## Your second mission: ship-it end to end

Pick something real but small — a feature you could build by hand in an afternoon — and, in a
Claude Code session opened in that repo, type:

```
ship this: add GET /healthz through the existing router.
Return version and DB connectivity, with 503 when the database is unavailable.
Test both responses using the project's integration-test command.
Stop at the promotion PR.
```

The run in phases (the full tour is in [the ship-it guide](missions/ship-it.md)):

**Phase 0 — preflight.** The coordinator checks `orca status`, verifies the integration BASE is
not your default branch (`runtime/scripts/preflight.py`), and confirms the suite is green at
baseline. A red baseline stops the run — otherwise the fleet cannot tell its regressions from
your pre-existing ones.

**Phase 1 — the grill (your part).** Since you gave intent, not a spec, the coordinator
interviews you: one question at a time, each with a recommended answer. Facts it can look up in
the codebase it does not ask about. When the decision tree is resolved it publishes a spec —
objectives, acceptance criteria, explicit non-goals, test seams — and asks you to **freeze** it.
This is human gate #1. After the freeze, scope does not silently reopen.

**Phase 2 — decompose and build.** The spec is cut into tracer-bullet slices; each slice gets a
fresh worker in its own worktree and terminal. Workers write the failing test first and touch
only what their slice requires. Concurrent builders stay within the
[attention budget](../runtime/attention-budget.md) (default ≤3) so review capacity keeps up.
Irreversible slices (auth, destructive migrations, secrets, …) write a plan and wait for a gate
before coding. You can watch, but nothing needs you until a one-way door.

**Phase 3 — review and prove.** Fresh sessions that did not write the code review each slice;
then the integrated whole is driven through its real entry point — for the example above,
an actual HTTP request to `/healthz` asserting the persisted response, plus a negative control
(revert the change, watch the test go red, restore).

**Phase 4 — land and stop.** A single conductor merges each reviewed slice into the integration
BASE, verifying ancestry and reviewed-SHA freshness. The fleet opens the BASE → default
**promotion PR** with a traceability table mapping every frozen criterion to a passing test, and
stops. Merging that PR is human gate #2 — always yours.

## What you will see while a fleet runs

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/first-run.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/first-run-light.jpg">
    <img src="../assets/diagrams/first-run-light.jpg" alt="A single command prompt fans out into a fleet of worker terminals over a node graph, converging into one evidence document stamped with a checkmark" width="820">
  </picture>
</p>

For a blow-by-blow of a real run — including the incidents and what the coordinator did about
them — read [Anatomy of a run](guides/anatomy-of-a-run.md), which walks the actual ledger of
the 2026-07-15 sweep of `dodopayments/chimely` hour by hour.

A fleet is not one scrolling transcript. Expect:

- **The coordinator terminal** — where you started. It narrates phases, dispatches, and
  verification results, and it is where gates surface.
- **Worker terminals** — one per active slice/finding, each in its own git worktree. They open,
  work, emit a manifest, and are torn down. You never need to type into one.
- **The ledger** — a file the coordinator keeps (its memory gets compacted; the ledger
  survives). One row per unit: id, flags, lighting, PR, reviewed SHA, merge SHA, evidence
  pointer. If you want to know where the run is, read the ledger, not the scrollback.
- **PRs on your repo** — one per unit of work, each targeting the integration BASE (never your
  default branch), each merged only by the conductor after verification.

## Where the evidence lands

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/artifacts-map.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/artifacts-map-light.jpg">
    <img src="../assets/diagrams/artifacts-map-light.jpg" alt="What a run leaves behind: a ledger with one row per unit; a docs/runs directory holding the report, a manifest per unit and a sha256 inventory; one PR per unit merged into BASE with reviewed_sha equal to head; and a promotion PR from BASE to default left to you" width="820">
  </picture>
</p>

Every unit of work produces a SHA-bound **evidence manifest** — the JSON contract described in
[concepts](concepts.md#the-evidence-manifest) and specified in
[`runtime/evidence-manifest.md`](../runtime/evidence-manifest.md). The parts worth reading as a
human:

- `base_sha` → `head_sha` — exactly what moved.
- `criteria[]` — every acceptance criterion from the frozen source, each marked addressed or
  not. The verifier re-derives this list; a worker cannot shrink it.
- `intent` — on mutation units: `goal` · `ruled_out` · `why`. Presence is checked; wisdom is
  not. Distinct from `claim`.
- `lighting` — `lit` (default) or `dark-eligible`. Dark only for Lane A work with an
  unfakeable oracle.
- `negative_control` — what was reverted or mutated, and proof the test went red.
- `commands[]` — real invocations with exit codes and artifact paths, not summaries.
- `claim` — the worker's own narration. Informational only; never the completion oracle.

When a coordinator says a unit is done, it means an independent verifier has already checked the
manifest against git, and the coordinator has re-run the suite in a clean environment at that
SHA — not that a worker said so. (The clean-env run is the coordinator's job, not `verify.py`'s;
[concepts](concepts.md#independent-verification) lists which check belongs to whom.)

## Your side of the human gates

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/diagrams/gates-terminal.jpg">
    <source media="(prefers-color-scheme: light)" srcset="../assets/diagrams/gates-terminal-light.jpg">
    <img src="../assets/diagrams/gates-terminal-light.jpg" alt="A freeze decision as it reaches your terminal: two options with one recommended, reply a or b, no timeout default because the freeze is a one-way gate; beside it a taste gate that takes the recommendation and keeps working for your later veto, and the promotion PR the fleet opens and leaves for you to merge" width="820">
  </picture>
</p>

Fleets classify every decision as **mechanical** (auto-resolved, audited), **taste**
(recommendation picked, batched for your veto, work continues), or **one-way** (yours, always).
You will be interrupted only for:

| Gate                             | When                       | What a good answer looks like |
|----------------------------------|----------------------------|-------------------------------|
| Freeze the spec                  | ship-it/map-it, intent entry | Read the acceptance criteria, not the prose. If a criterion is untestable, say so now — it is cheap here and expensive later. |
| Promotion to the default branch  | end of ship-it / clean-sweep | Review the traceability table and the `accountable:` line, then merge it yourself. |
| Refuted/duplicate closes (batch) | clean-sweep                | Skim the refutation evidence; approve as a batch or pull items out. |
| One-way remediations             | harden-it (e.g. secret rotation) | Do the action, then confirm — the mission counts it done only when *verified*, not when acknowledged. |

Here is what an actual gate looks like when it reaches you — a question from a freeze
session, recommendation attached, one question at a time:

```
DECISION (freeze grill) · spec/magic-link · token storage
  (a) signed JWT in the link — stateless, no schema change; revocation only by expiry  [recommended]
  (b) DB-backed one-time token — revocable, adds a table + a cleanup job
Reply 'a' or 'b'. No timeout default — the freeze is a one-way gate, and its questions wait.
```

Freeze questions block by design: the freeze itself is a one-way door, so nothing is defaulted
on your behalf. A **taste** gate mid-run looks similar but never blocks — the fleet takes the
recommendation, keeps working, and batches the decision for your later veto. Answer in one
character and the run moves; ask "why" and the coordinator argues its case. If the fleet
believes YOUR stated direction is wrong, that disagreement is never auto-decided — your
direction stands as the default while the fleet names its case, its blind spots, and the cost
of being wrong.

An unattended run never fakes your answer: unanswerable one-way questions get parked with the
run continuing elsewhere, or the run winds down and tells you what it was blocked on.

## What a run costs

No mission has a fixed price; the measured runs in the [archive](runs/README.md) are the honest
anchors. Rules of thumb from them:

- **One worker session per unit, plus its reviewers.** A unit is one finding, slice, flake or
  hypothesis; each gets a builder in a fresh worktree, a build-blind reviewer and, where it merges,
  an integrator turn. The [attention budget](../runtime/attention-budget.md) caps concurrent
  builders so review keeps up, which sets the wall clock more than model speed does.
- **A first `ship-it` is an overnight run, not a lunch break.** The one narrated run
  ([Anatomy of a run](guides/anatomy-of-a-run.md)) spans more than fourteen hours with five
  builder panes at its peak; the 2026-09-14 tracker close was ten units in two waves; the
  2026-09-21 `harden-it` self-run took ten waves to a clean re-audit.
- **A `review-it` dry run is cheap:** a few read-only worker sessions and no writes, which is why
  it is the first mission this guide recommends.
- **Activation alone costs context.** Every mission loads roughly a sixth of a 200k-token window
  before the first dispatch (each guide's Activation-load line has the number), so start a mission
  in a fresh session, never mid-conversation; the coordinator's own context compacts during a long
  run, which is why the ledger, not the scrollback, is its memory.

## Troubleshooting

The [troubleshooting guide](troubleshooting.md) gives concrete checks for installation, missing
skills, completion hooks, baseline failures and blocked PRs. The frequent first-run cases are
summarized here.

**"BASE is the default branch" and the run refuses to start.** Working as intended — fixes must
not land straight on production. Let the mission create its integration branch, or pass one that
forks from your default's history.

**A mission starts but workers never pick up tasks.** Check `orca status` and that the
`orchestration` skill is available in the worker context. The most common cause is running in a
repo where Orca is not initialized.

**A broken `../../ARCHITECTURE.md` link, or playbooks not found beside the skill.** You copied
a mission directory instead of symlinking it, or installed a single skill with a tool that
copies. Re-install per [Install the catalog](#install-the-catalog).

**The suite was red before the fleet started.** Fleets refuse to build on a red baseline.
Run [`deflake-it`](missions/deflake-it.md) (if the red is intermittent) or fix the deterministic
failures first — [`clean-sweep`](missions/clean-sweep.md) can drain them as findings.

**A worker died mid-run / the coordinator crashed.** Nothing is lost: liveness is watched, dead
workers are respawned in fresh terminals with bounded attempts, and a dead coordinator resumes
from the ledger + Orca provenance, re-verifying every completed unit against git before trusting
it. See [`runtime/liveness-resume.md`](../runtime/liveness-resume.md).

**You want to know why a decision was made.** Mechanical decisions are audited in the ledger
with their reasoning; taste decisions arrive batched in a brief you can veto. If a fleet made a
one-way decision without you, that is a bug — file it.

**A unit was marked done on a manifest that should have failed.** On a symlink install the
completion gate is not wired until the settings snippet is merged. `print-settings-snippet.sh
--check` cannot tell you: it only checks that the gate script exists in the clone. Look for the
two `verify-gate.sh` entries in `~/.claude/settings.json` and run the gate by hand against a
missing manifest, as shown under [Install the catalog](#install-the-catalog) — it must block. Remember what the gate checks from inside the worker's own session is advisory;
the sound surfaces are CI, an MCP task or an SDK subprocess
([docs/verify-gate.md](verify-gate.md#trust-boundary)).

---

Next: [Concepts](concepts.md) for the mental model behind fleets, or pick a
[mission guide](missions/) and go deep.
