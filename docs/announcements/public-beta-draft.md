# Public beta announcement — DRAFT, not published

**Status: draft.** This text is not posted anywhere. It is published only when every box under
[Gates before publishing](#gates-before-publishing) is checked, and it says only what the tree
supports at the 0.7.1 cut (`5331b9b`, the commit tag `v0.7.1` names — retargeted from 0.7.0
by the size gate below, whose rule made the announced release the first tag cut after the
shrink). The
[2026-09-28 release-readiness review](../reviews/2026-09-28-release-readiness-review.md#8-what-it-takes-to-release)
drew the line this draft follows: the version cut is release hygiene, the announcement is what
the P0 and P1 findings gate. A maintainer who posts this early is announcing claims the
evidence does not yet carry.

## Gates before publishing

Each row is a witnessed act, not a code change. The issue holds the evidence.

- [x] The release being announced is tagged, its provenance commit is recorded, and its GitHub
      Release exists ([#511](https://github.com/ravidsrk/orca-fleet/issues/511); the ops.md tag
      and record blocks, then the "Publishing Releases" block for the historical tags). The
      candidate is `v0.7.0` on `8a5211b`; the size row below can move it to a later tag, and
      then every version and SHA in this file changes with it before posting. Done twice over:
      tag `v0.7.0`, GitHub Release published 2026-09-30, provenance in `docs/releases.json`
      (#538); then retargeted — the announced release is `v0.7.1`, tagged 2026-10-13 at
      `5331b9b` with its GitHub Release published and provenance recorded (#552, #553).
- [x] The `dist` branch holds the 0.7.0 bundle (`publish-dist.yml` ran on the tag push) and the
      plugin install has been witnessed on a clean machine, transcript under
      `docs/completion/evidence/` per [the witness procedure](../completion/PLUGIN-INSTALL-WITNESS.md)
      ([#518](https://github.com/ravidsrk/orca-fleet/issues/518)). Done in #539: dist populated
      with 22 self-contained bundles at the cut; `CF-02b-plugin-install.txt` /
      `CF-02b-plugin-uninstall.txt` retained; #518 closed.
- [x] The receipt trees under `docs/runs/` and `docs/reports/` are shrunk or relocated out of
      the plugin copy (review P1-5, the third part of #518), and the tree of the announced
      tag is the shrunk one. The plugin path copies the marketplace's default-branch tip, and
      the `dist` branch and any tag-based install copy the tag, so both must carry the shrink:
      if it lands after `v0.7.0`, the announced release is the first tag cut after it, not
      0.7.0. The witness transcript's `du -sh`, re-run at that tag's commit, shows the reduced
      size. Disclosing the full size is not a substitute: the review requires the copy to
      shrink before a public beta, and this box stays unchecked until it has.
      Done 2026-10-13 by building it: the bundle now emits the plugin manifest, hooks, and
      gate runtime, and the marketplace sources the plugin from the `dist` branch (#551),
      so a plugin install copies the generated tree, not the source tree. Witnessed at the
      announced tag: `CF-02c-lean-plugin-install.txt` — installed copy 24M (was 66M),
      22 skills + both hooks discovered, and all 1,652 paths of a bundle rebuilt from the
      tagged commit fingerprint-match the installed copy (published dist tree matches as
      a second check); uninstall half retained alongside (the host keeps the deregistered
      cache on disk; recorded, not hidden). First tag carrying the shrink: `v0.7.1`.
- [x] One recorded `review-it` or `ship-it` run on an Ubuntu host driven by `orca-ide`, so the
      Linux sentence below can drop the word "untested" (review §8, item 6). Done 2026-10-13:
      `review-it` on Ubuntu 24.04 via `orca-ide` 1.4.224, NO-GO verdict bound to the reviewed
      SHA (`docs/runs/2026-10-13-review-it-linux.md`, #527); the sentence below names it.
- [ ] An external monitor polls the Actions API for `main`'s latest `validate` conclusion
      (`docs/ops.md`, incident step 1), so a no-runner outage is seen by something outside
      Actions ([#520](https://github.com/ravidsrk/orca-fleet/issues/520)'s outer layer).
      Status 2026-10-13: NOT done — the poller and guide landed (#540), the watch is
      configured but paused pending maintainer activation (#528).
- [ ] The proof paragraph below still matches the README's generated proof-status sentence on
      the day of posting. If an external `ship-it` run has bound by then
      ([#515](https://github.com/ravidsrk/orca-fleet/issues/515)), say so; if not, the
      paragraph makes no such claim and needs no edit. Refreshed 2026-10-17: both the external
      `ship-it` run (#549) and the external `review-it` run (#529) have bound, so the paragraph
      now names both; this box is ticked only by re-checking the match on the day of posting.

## The text

### Title

orca-fleet 0.7.1: outcome-named autonomous fleets for the Orca runtime, now in public beta

### Body

orca-fleet is a catalog of missions for the [Orca](https://github.com/stablyai/orca) runtime.
Each mission is named for an outcome, never for a technique: `ship-it` turns a spec into a
released, verified change; `clean-sweep` drains a backlog; `harden-it` closes a security loop;
`prove-it` closes a test gap. A mission dispatches workers into isolated git worktrees, holds
them to a definition of done that is an evidence protocol rather than a narration, and hands
you pull requests against an integration branch. Promotion to your default branch is always
your click.

**What "beta" means here.** Every mission carries a proof tier that a validator enforces and a
test binds to the README's catalog table. Today two missions, `ship-it` and `review-it`, stand
at `external-run`: they were run against repositories outside this catalog (a new CLI built
from a frozen spec to a reviewed, verified `BUILT`, and a cross-repo PR review verdict), and
their run reports re-hash at the commits they name. Three missions, `clean-sweep`, `harden-it`
and `prove-it`, stand at `self-run` on the same standard.
Every other mission stands at `doctrine-only`: written, validated, exercised in the self-test
campaign, and not yet bound to a run a stranger can re-derive. The
[run archive](../runs/README.md) records every run that really happened and says, per run,
whether it binds. If you run a doctrine-only mission and file the bundle through the
[call for runs](../call-for-runs.md), the tier advances on your evidence.

**What it does to your machine.** Workers run your coding agent with its permission prompts
off, because a worker that blocks on a prompt kills the run. Orca's worktree is an isolated
checkout, not a security sandbox. Each worker opens pull requests on your repository; the fleet
never merges to your default branch. The completion gate is advisory inside a worker's own
session; the sound verification surface is off-worker, in CI or a process the worker cannot
influence. For a first run use a repository you can afford to lose, a VM, or the `offload-it`
recipe. The full boundary is stated in the README under
[Before you run a mission](../../README.md#before-you-run-a-mission).

**What you need.** The Orca app running with the orchestration experimental feature enabled, at
or above the catalog pin (`runtime/pins.json`, v1.4.224 at the 0.7.1 cut; v1.4.229 on `main`); the `orca` CLI, which is
`orca-ide` on Linux; Orca's `orchestration` and `orca-cli` skills installed for your agent host;
`git` and `gh`; Python 3.11 or newer. Most recorded runs happened on macOS; Linux, supported
by the code as of 0.7.1, has two recorded runs on Ubuntu via `orca-ide`: a `review-it` verdict
(`docs/runs/2026-10-13-review-it-linux.md`) and the full external `ship-it` build
(`docs/runs/2026-10-13-ship-it-mdtoc.md`).

**Install.** Symlink individual missions into your agent's skills directory (the verified path),
or install the whole catalog as a Claude Code plugin, which is the one path that wires the
completion gate by construction. Copy installers, including the `skills` CLI, must point at the
`dist` branch, never at the repository root. The [install page](../install.md) has every path
and says which ones carry the gate.

**Support window.** The catalog is re-witnessed against the installed Orca binary on every
re-pin; 0.7.1 was tested against v1.4.209 through v1.4.224 (and re-pinned through v1.4.229 on `main`). Orca ships almost daily, so a weekly
probe files an issue when the pin falls behind, and a quarterly re-pin runs regardless.

**What is not claimed.** Only `ship-it` and `review-it` are `external-run`, and `ship-it`'s run stopped at `BUILT` on an
integration branch — no release or deployment state beyond that is claimed for any mission. The verifier hashes evidence and re-derives
bindings; it does not re-run your tests for you. Nothing here is affiliated with or endorsed by
Stably, the Orca maintainers, or the authors of the upstream skill packs whose techniques the
workers use; those are credited in the README and in `THIRD_PARTY_NOTICES.md`.

**How to help.** Run a mission and file the bundle ([call for runs](../call-for-runs.md), then
the [submission guide](../run-submission-guide.md)). Report what breaks through the issue
templates. The [code of conduct](../../CODE_OF_CONDUCT.md) applies everywhere the project
talks.

**What comes next.** 1.0 is defined by an executable checklist, `scripts/release_check.py`,
which prints one verdict per gate and exits non-zero on a standing skip. The road from this
beta to that release is a tracked epic on the issue tracker.

### Closing line

Cut from `8a5211b` (or the announced tag's cut, per the gate list); every frozen gate green in
CI at that commit. Release notes are the CHANGELOG section the tag carries.

## Where it goes, in order

1. The GitHub Release body for `v0.7.1` (already generated from the CHANGELOG by
   `release.yml`; this text is the human summary above it, added by editing the Release).
2. The repository README, one line under the title, linking the Release.
3. The listings the [distribution page](../distribution.md) tracks, each led by the proof
   framing, never by a catalog count.
4. Anywhere else the maintainer chooses, with the same text and no stronger claim.
