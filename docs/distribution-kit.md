# Listing kit: paste-ready copy for H-02 (#235)

[Distribution](distribution.md) · [About text](about.md) · [Proof reports](runs/README.md)

This page is the copy for the marketplace submissions that only the maintainer can make (H-02 in
[HUMAN_ACTIONS](completion/HUMAN_ACTIONS.md), issue #235). An agent wrote it and submitted
nothing. Each submission happens under the maintainer's own account. When a listing goes live, post
its URL on #235. The agent step then flips that row in
[distribution.md](distribution.md#ecosystem-directory--indexer-status).

## The `proof:` framing (lead with this everywhere)

Every listing opens with what a mission's `proof:` field means, not with a feature list. Each
mission declares `metadata.proof:` as `doctrine-only`, `self-run` or `external-run`. A mission
moves past `doctrine-only` only through a run report that binds: a `RUN:` header, a manifest in
the run's own directory, and an inventory that re-hashes at the commit it names. Today the
22-mission catalog holds 2 external-run (`ship-it`, `review-it`), 3 self-run (`clean-sweep`,
`prove-it`, `harden-it`) and 17 doctrine-only missions. Before pasting, re-read the counts with
`python3 runtime/scripts/proof_status.py`. `tests/test_docs_navigation.py` fails if a tier count
or a catalog total on this page falls behind. Quoted stale text sits in fenced blocks, which the
test skips.

Never describe a doctrine-only mission as proven, and never claim a listing, an install count or a
does-it-load score that doesn't exist yet.

## Per-aggregator blurbs

### Anthropic plugin directory (`anthropics/claude-plugins-official`)

- **Submit at:** the signed-in [developer portal](https://claude.ai/directory/manage). It answers
  403 to a signed-out request. The public [submission link](https://clau.de/plugin-directory-submission)
  redirects to [Publish to the directory](https://claude.com/docs/directory/publish).
- **How:** choose **Plugin bundle**, enter repository `ravidsrk/open-fleet` and branch **`dist`**.
  [distribution.md](distribution.md#directory-specific-entry-anthropicsclaude-plugins-official) has
  the validation history, the policy holds the bundle README discloses, and the JSON entry.
- **Blurb:**

  > **proof: 2 external-run · 3 self-run · 17 doctrine-only. Each self-run and external-run
  > mission is bound to a re-hashable run report.** open-fleet is 22 outcome-named autonomous fleets for coding agents
  > on Orca, POSIX and multi-runtime orchestrators. Each mission is one outcome with its own state
  > machine. A unit of work is done only when an independent verifier re-derives its SHA-bound
  > evidence manifest, never on a worker's narration. One router per worker. MIT.

### claudemarketplace.net

- **Submit at:** the [submit page](https://www.claudemarketplace.net/submit). It takes listings
  by email to `chekkutech@gmail.com` (or WhatsApp) and reviews each one by hand.
- **Fields:** name, logo, install line, repository and category, from
  [distribution.md](distribution.md#claudemarketplacenet).
- **One-line summary:** *Autonomous fleets that publish their `proof:` tier: 2 external-run and
  3 self-run missions bound to run reports, 17 doctrine-only.*
- **Longer description:** the Anthropic directory blurb above, followed by the proof link
  `https://github.com/ravidsrk/open-fleet/tree/main/docs/runs`.

### skills.sh

- **Listing:** [skills.sh/ravidsrk/orca-fleet](https://www.skills.sh/ravidsrk/orca-fleet). The
  listing still uses the old repository name, and `skills.sh/ravidsrk/open-fleet` returned 404 on
  2026-10-31.
- **How it updates:** there's no submission form. The listing was registered by first-install
  telemetry. Don't run the installer just to force a refresh: that would fabricate an install event.
- **Blurb**, if skills.sh ever offers an editable description:

  > **proof: 2 external-run · 3 self-run · 17 doctrine-only.** 22 outcome-named missions for
  > coding agents, each closing on an independently verified, SHA-bound evidence manifest.

### buildwithclaude.com

- **Listing:** [search](https://buildwithclaude.com/api/search?q=orca-fleet). It's auto-indexed
  from GitHub, so there's no submission.
- **Contact channel for a re-index:** an issue on
  [davepoon/buildwithclaude](https://github.com/davepoon/buildwithclaude/issues) (the site's own
  repository, linked from its footer). The site has no contact page; `/contact` returned 404 on
  2026-10-31.
- **What is stale (read 2026-10-31):** the `marketplace` record `@ravidsrk/orca-fleet` was
  re-crawled on 2026-10-28 and still reads:

  ```text
  10 outcome-named autonomous fleets for the Orca runtime — SHA-bound evidence definition of done, best-of-breed worker recipes, one router per worker.
  ```

  That's a cache of a long-gone About string. The count, the runtime and the name (`orca-fleet`)
  are all wrong. The `plugin` record (2026-10-07) is count-free but still points at
  `github.com/ravidsrk/orca-fleet`.
- **Replacement blurb** to ask for. It's the canonical [About text](about.md), which is count-free
  so it can't go stale the same way:

  > Outcome-named autonomous fleets for coding agents across Orca, POSIX, and multi-runtime
  > orchestrators — SHA-bound evidence definition of done, best-of-breed worker recipes, one
  > router per worker.

  Also ask them to update the name to `open-fleet` and the repository URL to
  `https://github.com/ravidsrk/open-fleet`.

## Submission URLs at a glance

| Aggregator | Where | Account needed |
|---|---|---|
| Anthropic plugin directory | <https://claude.ai/directory/manage> | the maintainer's Claude account |
| claudemarketplace.net | <https://www.claudemarketplace.net/submit> (email `chekkutech@gmail.com`) | the maintainer's email |
| skills.sh | none (telemetry-registered) | — |
| buildwithclaude.com | <https://github.com/davepoon/buildwithclaude/issues> (re-index request) | the maintainer's GitHub account |
