# Distribution, discoverability & trust

[Documentation](README.md) · [Install](install.md) · [Maintainer ops](ops.md)

*How orca-fleet reaches users, and what its proof records establish.*

For setup commands, updates and removal, use [Install](install.md). This page records
packaging mechanisms, evidence limits and dated directory checks for maintainers. Each
index check describes its recorded date; it does not establish today's listing status.

> Trust guidance checked 2026-09-12. Historical index check 2026-09-01 (issue #210).
> Submissions that need a human account remain [H-02](completion/HUMAN_ACTIONS.md).

## State the evidence and who checks it

Listings should link to retained evidence and identify its authority:

- **Deterministic checks:** the validator checks catalog structure, declared autonomy levels,
  generated badge freshness and proof-report bindings. A tier above `doctrine-only` requires
  a retained report with an inventory that re-hashes at its named commit. These checks do not
  establish that a mission achieved its outcome. See the [run archive](runs/).
- **Worker-attested records:** `commands[]`, provenance and recorded verifier outcomes originate
  in the worker's environment. `run_report.py` checks bindings and hashes; it does not rerun
  verification or independently authenticate the worker's ledger.
- **Coordinator-owned reruns:** an independent process must use the frozen contract, inspect
  authoritative git/review state, rerun tests in a clean environment at the exact SHA, and execute
  the applicable negative control. Deploy/review identity also needs a coordinator check when
  shipping. Installing the catalog does not perform these steps.
- **Advisory native hooks:** `Stop`/`TaskCompleted` hooks run in the worker's session, where inputs
  and keys are worker-influenceable. They provide local checks; independence requires execution
  outside that session with coordinator-controlled inputs. See the
  [gate trust boundary](verify-gate.md#trust-boundary).

Badge freshness binds generated counts to repository state. A discovered test count does not
establish that the tests passed; use an actual CI result for execution status. Lead listings with
these specific guarantees and their limits, alongside the available run evidence.

## Install paths (already shipped)

| Path | For | Mechanism |
|---|---|---|
| Plugin marketplace | try the whole catalog | `/plugin marketplace add ravidsrk/orca-fleet` → `/plugin install orca-fleet@orca-fleet` (`.claude-plugin/`); see [Install](install.md#claude-code-plugin) for activation and witness status |
| Symlink the catalog | fork/adapt, or evaluate | `git clone https://github.com/ravidsrk/orca-fleet.git && cd orca-fleet && sh scripts/install.sh` (validates + links every mission; preserves the relative `playbooks/`/`runtime/` refs) |
| Skill bundle link | a subset on this or a paired host | open the maintainer's unlisted Skills → Share skills link: inspect the exact version, pick all or a subset of its skills, choose global or workspace scope (this computer, a paired runtime, WSL, an SSH host); update, roll back, or remove via Skills → Manage installs |

## Self-containment: what a single copied mission loses

A mission in this repository is **not** self-contained. `skills/<name>/SKILL.md` names its
playbooks and runtime policies by bare name and links `../../ARCHITECTURE.md`; those files live
in `playbooks/`, `runtime/` and the repository root. Copy one `skills/<name>/` directory alone
into a registry or a skills folder and every one of those references dangles — the mission still
loads, and runs half-blind with nothing saying so. The symlink install and the plugin keep the
tree intact, which is why they are the supported paths.

`scripts/bundle.py` is the fix for copy installers, and it does vendor per mission: each
`dist/skills/<name>/` carries `references/` (every playbook and runtime policy the mission
composes or rides, their transitive references, and `ARCHITECTURE.md` when the mission links
it), a generated `references/README.md` index that resolves the bare names, `runtime/scripts/`
plus the runtime JSON (`pins.json`, `one-way-doors.json`, `quarantine.json`, …), and
`docs/runs/TEMPLATE.md`; outbound links in SKILL.md are rewritten to those copies. Limits that
remain: the vendored commands expect `ORCA_FLEET_ROOT` exported to the installed mission
directory; the completion-gate hooks ship at the bundle root (the plugin), not inside each
mission; and every mission carries its own copy, so a copied mission does not pick up a later
doctrine fix until it is re-bundled. A registry listing should point at the `dist` branch, never
at `skills/<name>/` in the source tree.

## Prerequisites, pinned

Two classes. *Install* prerequisites must hold or `scripts/install.sh` exits 1;
*run* prerequisites warn only — the catalog installs and verifies without them,
but no mission will dispatch until they clear.

| Prerequisite | Class | Enforced | Observed 2026-09-16 |
|---|---|---|---|
| `git` | install | present (hard) | 2.47.3 (clean container), 2.55.0 (macOS host) |
| `python3` | install | ≥ 3.11 (hard; CI runs the suite on 3.11, 3.12 and 3.13, #514) | 3.13.15 |
| Orca app + CLI | run | ≥ the `runtime/pins.json` pin, currently v1.4.229 (warn; `scripts/validate.py` fails when this number and the pin disagree, #512) | v1.4.229 source-delta re-witness (2026-10-17) + installed app + CLI live-witnessed on macOS + Linux serve (`pins.json` `witness_binary`) |
| `gh`, authenticated | run | present + `gh auth status` green (warn) | 2.100.0 |
| Claude Code | run | present (warn; the symlinked skills load under it) | 2.1.272 |

The Orca floor is read from `runtime/pins.json` at install time, not copied into
the script — a pin-it re-pin moves the floor with no installer edit. The clean-
container run that fixed this table is
[414-clean-container-install.txt](completion/evidence/414-clean-container-install.txt):
from `python:3.13-slim` the only setup was `apt-get install git ca-certificates`
(the image ships no git), then the one command above exited 0 with the three
expected run-substrate warnings, and `sh scripts/install.sh --check` re-verified
without changes. `.github/workflows/install.yml` repeats that shape — empty HOME,
no credentials — on every PR touching an install path.

## Index check (2026-09-28; previous 2026-09-21, 2026-09-13, 2026-09-01)

**Re-run 2026-09-28: two rows moved, two hold.** Every row re-measured against its live
surface; the catalog is 22 missions (`offload-it` merged 2026-09-26, #505).

- buildwithclaude RE-INDEXED: both records now carry `updatedAt` **2026-09-19**
  (marketplace `05:02Z`, plugin `05:54Z`) — but the marketplace record's blurb STILL reads
  "10 outcome-named autonomous fleets". A second record, type `plugin` / slug `orca-fleet`
  (first noted this run — prior checks recorded only the marketplace hit), carries
  count-free copy drawn from the refreshed repo description. Raw-value honesty note: the
  2026-09-21 check reported `updatedAt` 2026-09-01, two days AFTER the 09-19 timestamp
  these records carry today — either that read hit a cached API response or the field
  backdates the source change rather than the crawl. Both records: 0 installs, no score.
- skills.sh still lists **21** skills (no `offload-it`) at 21 total installs — the listing
  lags the catalog by one mission. Refresh path unverified: the site documents no
  submission form and no crawl schedule, and re-running the installer would fabricate an
  install event, so this run declined to touch it. The 2026-09-23 box stays checked (the
  listing is live; the predecessor is history) with the lag noted.
- claudemarketplace.net still returns the literal `No results for "orca-fleet"` — holds.
- anthropics/claude-plugins-official graduates from **unverified** to **verified no**:
  the repo API answers again (200, was 403), the marketplace file lives at
  `.claude-plugin/marketplace.json` — the root-path 404 all three prior checks recorded
  was a wrong-path artifact — and its full content (548 `"name"` hits) plus a recursive
  tree search contain zero mentions of `orca-fleet`/`ravidsrk` at 2026-09-28.

Still no indexer publishes a does-it-load score for this catalog. One upstream DID move:
the GitHub About text is count-free today (the `about.md` copy, applied at some point
since 2026-09-21) — so buildwithclaude's surviving "10" is now definitively their cache,
not our setting: either the 09-19 crawl predates the About edit or that field is sticky
across crawls. Retiring it needs a re-index request through their contact channel —
human, like the remaining submission boxes.

## Index check (2026-09-21; previous 2026-09-13, 2026-09-01)

**Re-run 2026-09-21: still nothing moved.** Every row re-measured against its live surface;
all four 2026-09-13 rows hold unchanged:

- buildwithclaude's record STILL carries `updatedAt` **2026-09-01** — no re-index in twenty
  days; the blurb still reads "10 outcome-named autonomous fleets" (the catalog is 21; the
  About is 17). The repo-setting About text remains the upstream of that row and only the
  maintainer can change it.
- skills.sh still indexes the predecessor `ravidsrk/autonomous-fleet` (2 installs) for the
  `ravidsrk` query; `ravidsrk/orca-fleet` still resolves to stablyai/orca's skills, not this
  catalog.
- claudemarketplace.net still returns the literal `No results for "orca-fleet"` (the slug
  appears only as the echoed query in title/input — the result payload is empty; the
  2026-09-13 trap note stands: match on the payload, never the page).
- anthropics/claude-plugins-official's `marketplace.json` still returns HTTP 404 — the row
  stays **unverified**, now at 2026-09-21 as well, never re-confirmed.

## Index check (2026-09-13; previous 2026-09-01)

Agent-reachable surfaces. "Listed" means a search returned this repo, not that
a human submitted it.

**Re-run 2026-09-13: nothing moved in twelve days** — with one row that was not re-checked and
says so. buildwithclaude, skills.sh and claudemarketplace.net were re-measured against their live
endpoints and hold. The self-hosted marketplace is the documented install path and
`agentskills validate` is a local check, so neither depends on an indexer.
`anthropics/claude-plugins-official` could NOT be re-checked and carries
`(unverified 2026-09-13)` in the table itself: read its `no` as of 2026-09-01, not today.

Holding is the expected result while #235 (H-02) is unactioned — these surfaces need a human with
submit rights, so an agent re-check can only confirm the gap, never close it. Two details
sharpened:

- buildwithclaude's record still carries `updatedAt` **2026-09-01** — it has not re-indexed
  since the first check — and its blurb reads *"10 outcome-named autonomous fleets"*. That is
  a cache of an older GitHub **About** string, which itself now reads 17, against a catalog of
  **21**. Three different counts are in circulation and none of them is right. The About text
  is a repository setting, not a file in this tree; fixing it is the upstream of this row.
  The text to paste is now checked in at [about.md](about.md) and carries no count at all —
  the same way `plugin.json` and `marketplace.json` already describe this catalog — so a
  re-index after the maintainer applies it cannot reintroduce a number that goes stale.
- claudemarketplace.net returns the literal page text `No results for "orca-fleet"`. The
  string `orca-fleet` does appear three times in that HTML — in the title, the search input's
  `value`, and the no-results line — so grepping the page for the slug reports a hit that is
  only the query echoed back. Match on the result payload, not the page.

`anthropics/claude-plugins-official` could not be re-checked from here: `marketplace.json`
returns HTTP 404 at that path and the repository API returns 403 for this session. Its row is
carried forward from 2026-09-01 and is **unverified at this date** rather than re-confirmed —
said in the row as well as here, because a reader scanning a table dated today will not find a
caveat three paragraphs above it (PR #342 review).

| Surface | Listed? | Evidence |
|---|---|---|
| Self-hosted marketplace | yes | `/plugin marketplace add ravidsrk/orca-fleet` (already the install path) |
| [buildwithclaude.com](https://buildwithclaude.com/api/search?q=orca-fleet) | yes (auto-index) | two records, both `updatedAt` 2026-09-19: the marketplace hit `@ravidsrk/orca-fleet` still carries the stale "10 outcome-named" blurb, while a `plugin` / `orca-fleet` record (first noted 2026-09-28) carries count-free copy. 0 installs each; the GitHub About is count-free since ≤2026-09-28, so the surviving "10" is their cache — needs a human re-index request |
| [skills.sh](https://www.skills.sh/ravidsrk/orca-fleet) | **yes (2026-09-23)** | listing live: 21 skills at 21 total installs (was `0 total installs` at registration) — but the catalog is 22 since #505, so the listing lags by `offload-it` (2026-09-28). skills.sh has no submission form; the first `npx skills add ravidsrk/orca-fleet` registers the repo, so the agent slice ran it from a scratch HOME. CAUTION for any re-run: the installer's symlink mode rewires the CWD's skills/ tree into `.agents/` symlinks — run it from a throwaway directory, never from the repo root (the 2026-09-23 registration needed a full `git checkout -- skills/` repair) — and a re-run would fabricate an install event, so do not refresh the listing that way. The predecessor `ravidsrk/autonomous-fleet` listing remains as history |
| [claudemarketplace.net](https://www.claudemarketplace.net/search?q=orca-fleet) | no | search payload `skills: []`, `mcpServers: []` |
| [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | no **(verified 2026-09-28)** | the file is `.claude-plugin/marketplace.json` — the root-path 404 was a wrong-path artifact. Full content (548 `"name"` hits) plus a recursive tree search: zero mentions of `orca-fleet`/`ravidsrk`. Still needs the human submission-form round |
| `agentskills validate` | name/description/compatibility/license pass | extras `proof`/`autonomy`/`proof_evidence` are intentional (issue #211) |

No indexer currently publishes a does-it-load score for this catalog (buildwithclaude
`installs: 0`).

## External submission checklist (H-02)

These still need an account with rights to submit. Do not flip them from a clone:

- [ ] Submit to **anthropics/claude-plugins-official** (their plugin-directory form) and to
      **claudemarketplace.net** (email/message submission) — the paste-ready kit is the
      section below.
- [x] Get `ravidsrk/orca-fleet` onto **skills.sh** so the predecessor listing is not the
      hit — DONE 2026-09-23: [skills.sh/ravidsrk/orca-fleet](https://www.skills.sh/ravidsrk/orca-fleet)
      is listed (registration is first-install telemetry, run from a scratch HOME) — but
      listed ≠ up to date: 21 skills at 2026-09-28, one behind the 22-catalog (`offload-it`);
      no refresh path short of another install event, which would fabricate telemetry.
- [ ] Confirm a green **"does-it-load"** score once an indexer actually scores the pack.
- [ ] On every listing a human files, lead with the **`proof:` trust badge** framing + a
      link to the [run archive](runs/). The buildwithclaude auto-index currently leads with
      a stale catalog-count blurb — replace that copy when a submit form exists.
- [x] `agentskills.io` required fields pass locally; extras documented (issue #211).

## Submission kit (paste-ready, maintainer's round)

Shared lead for every listing (the `proof:` framing; live index re-checked 2026-10-17):

> Orca-fleet is 22 outcome-named autonomous fleets for the Orca runtime. Each mission is one
> outcome with its own state machine and an evidence-backed definition of done: every unit of
> work closes with a SHA-bound evidence manifest an independent verifier re-derives, never a
> worker's narration. Its own catalog holds five binding proof reports — two external-run
> (`ship-it`, `review-it`) and three self-run (`clean-sweep`, `prove-it`, `harden-it`) — the
> same standard it asks of your repo. One router per worker; MIT.
> Install: `/plugin marketplace add ravidsrk/orca-fleet`
> Proof: https://github.com/ravidsrk/orca-fleet/tree/main/docs/runs

**anthropics/claude-plugins-official** — the [official submission link](https://clau.de/plugin-directory-submission)
now redirects to [Publish to the directory](https://claude.com/docs/directory/publish)
(rechecked 2026-09-30). Use the signed-in [developer portal](https://claude.ai/directory/manage),
choose **Plugin bundle**, and submit the public repository's root folder. The older Console
submission form is no longer supported. A submission still needs Anthropic's validation,
security scan and human review before a listing goes live; submission is not approval. The catalog is already a conforming marketplace repo
(`.claude-plugin/marketplace.json` + `plugin.json` at the root); the entry to offer:

```json
{
  "name": "orca-fleet",
  "description": "Outcome-named autonomous fleets for the Orca runtime — each mission is one outcome with a SHA-bound, independently re-derived definition of done. Five missions carry binding proof reports (two external-run, three self-run).",
  "author": { "name": "Ravindra Kumar", "email": "ravidsrk@gmail.com", "url": "https://github.com/ravidsrk" },
  "category": "development",
  "source": { "source": "github", "repo": "ravidsrk/orca-fleet" },
  "homepage": "https://github.com/ravidsrk/orca-fleet"
}
```

**claudemarketplace.net** — email chekkutech@gmail.com (or their message button) with their
requested fields, filled:

- Name: orca-fleet
- One-line summary: Outcome-named autonomous fleets for Orca — evidence-backed done, never narration.
- Longer description: the shared lead above + the README link.
- Install: `/plugin marketplace add ravidsrk/orca-fleet` (Claude Code plugin system).
- Repository: https://github.com/ravidsrk/orca-fleet · Docs: same, `docs/`.
- Logo: `assets/social-preview.jpg` (1200px; crop to 128px+ as needed).
- Suggested category: Developer Tools / Agent Skills.

**buildwithclaude** — auto-indexed; the stale blurb is from an old scrape (the repo
description was refreshed since). Ask for a re-index through their contact channel with the
shared lead as the replacement copy.

## Optional: a proof-status badge

A future `assets/badges/proof.json` (generated by `scripts/gen-badges.py`, checked by
`check_badge_freshness`) could surface the catalog's proof mix as `runtime/scripts/proof_status.py`
reports it — at this writing 2 external-run · 3 self-run · 17 doctrine-only, figures the navigation
test binds to the live rollup so they cannot rot silently — in the README badge row, turning honesty
into a visible summary of retained proof records.
Deferred here to keep this change doc-only; tracked as a follow-up.

## See also

- [Proof over doctrine](../ARCHITECTURE.md) · [run archive](runs/) · [platform-ride & absorption risks](platform-ride.md)
