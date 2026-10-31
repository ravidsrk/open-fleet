# Ops — account inventory and incident process

[Documentation](README.md) · [Contributor setup](development.md) · [Release checklist](release-1.0-checklist.md)

Bus factor 1: Ravindra Kumar ([`ravidsrk`](https://github.com/ravidsrk),
`ravidsrk@gmail.com`). This page is the inventory of surfaces that can
break the catalog, and what to do at 2 a.m. It is not a product runbook —
missions already have those.

## Account inventory

| Surface | Account / handle | Lives in | Notes |
|---|---|---|---|
| GitHub | `ravidsrk` | [ravidsrk/open-fleet](https://github.com/ravidsrk/open-fleet) | source of truth, Actions (`validate` gates + `negative-control-demo` pinned-demo gate; `alert-on-failure` files a `ci-failure` issue when either fails on `main`), private vulnerability reporting |
| GitHub peer review | `agentsalpha` (designated second maintainer) | [Repository invitations](https://github.com/ravidsrk/open-fleet/invitations) | write invitation `335422854` sent 2026-09-30, never accepted; OpenAI Codex is the second reviewer instead (#595, below); role boundaries below |
| Claude plugin marketplace | GitHub self-host + buildwithclaude auto-index | [`.claude-plugin/`](../.claude-plugin/plugin.json) | `/plugin marketplace add ravidsrk/open-fleet`; external listing history and submission status are in [distribution](distribution.md) |
| greptile | removed 2026-10-27 | [greptile.com](https://greptile.com/) | no longer a GitHub check on PRs, a required context on `main`, or part of the review loop; Codex is the second reviewer (#595, below) |
| agentskills.io listing | not submitted | local `uvx --from skills-ref agentskills validate` | repository claims (`proof`, `autonomy`, `proof_evidence`) live under `metadata:` — [CONTRIBUTING](../.github/CONTRIBUTING.md) |
| Maintainer email | `ravidsrk@gmail.com` | [SECURITY.md](../.github/SECURITY.md) | security reports (72h ack) and ops contact |

This inventory records no separate production host for the catalog. A source change lands on
`main`; immutable release publication is a separate step. A `v*` tag triggers the dist and
GitHub Release publishers described under [Publishing Releases](#publishing-releases).

## Maintainer roles

`ravidsrk` remains the release maintainer: only Ravindra authorizes the exact version and
cut SHA before tagging, answers this catalog's one-way gates, and approves floor-guard
waivers through the existing recorded-waiver process. Write access alone does not delegate
those decisions.

`agentsalpha` is the designated second maintainer for ordinary code review and protected
merges. A write invitation was sent on 2026-09-30 (GitHub invitation `335422854`);
it was never accepted, so peer ownership never became effective. Ravindra
authorized preparing the ownership entries in #541 while acceptance was pending.
CODEOWNERS covers `runtime/`, `scripts/`, `.github/` and this page. Each maintainer
reviews the other's changes on these paths. Approval does not permit bypassing the required
checks, changing an immutable tag, or treating a review from the author as an independent
review. #530 closed on 2026-09-30 without that review; H-10 in HUMAN_ACTIONS is done
instead by the owner's disposition (#595, below).

## CI runners

Since #735 (2026-10-29), most jobs run on AWS CodeBuild-hosted GitHub Actions runners. A job
asks for one with `runs-on: codebuild-gha-open-fleet-${{ github.run_id }}-${{ github.run_attempt }}`.
The label names the CodeBuild project, and the run ID and attempt make each job's runner
single-use. List them with `rg -n codebuild-gha-open-fleet .github/workflows`.

| Runs on | Jobs | Why |
|---|---|---|
| CodeBuild | `guard` (guard.yml), `pinned-demo` (negative-control.yml), `from-scratch` (install.yml), `bind` (bind-check.yml), `pytest`, `ruff` and `migrate` (fixture-target-app.yml), `probe` (upstream-drift.yml), `health` (main-health.yml), `alert` (alert-on-failure.yml), `relay` and `verdict` (verdict-check.yml), `resolve` and `gate` (verdict-gate.yml) | the pilot's default |
| GitHub-hosted `ubuntu-latest` | `tests`, `floor`, `checks`, `vfbench` and `vfbench_replay` (validate.yml) | they need a non-root user and system-custody git. CodeBuild runs as root, where the ownership-boundary tests would skip silently. |
| GitHub-hosted | `gates` (validate.yml) | it combines the coverage recorded on the GitHub-hosted shards, and those paths are runner-specific |
| GitHub-hosted | `smoke` (fixture-target-app.yml) | it pulls from Docker Hub, and CodeBuild's shared IPs hit the anonymous pull limit |
| GitHub-hosted | `dist` (publish-dist.yml), `publish` (release.yml) | release publishing stays on GitHub-hosted runners for npm provenance |

A CodeBuild job sets up Python with `actions/setup-python` and then registers its `libpython`
with `ldconfig` (the step named "register setup-python's libpython with ldconfig (CodeBuild
runners)"). Without that step, a subprocess that drops `LD_LIBRARY_PATH` cannot load Python.

**AWS prerequisites.** Both are account settings, not files in this tree. Only the owner changes
them.
- A CodeBuild project named `gha-open-fleet` in `us-east-1`, configured as a GitHub Actions
  runner project for this repository. It reports its own check, "AWS CodeBuild us-east-1
  (gha-open-fleet)", on each run.
- An AWS CodeConnections GitHub connection that gives that project access to
  `ravidsrk/open-fleet` and its workflow-job webhook.

**Forks and contributors.** A pull request from a fork into this repository runs here, so its
CodeBuild jobs use this project like any other PR, once a maintainer approves the run where
the repository's fork-approval setting asks for it (it did for #741). A fork running CI in its own repository
has no `gha-open-fleet` project, so those jobs sit in "Queued" until GitHub cancels them after
24 hours. To run them there, change the fork's own copy of each `runs-on: codebuild-gha-open-fleet-…`
line to `runs-on: ubuntu-latest`. The libpython step is a no-op where it is not needed. Never send
that edit upstream: a PR that changes `.github/workflows/` from a fork fails `verdict-gate`
(the grader rule above).

**A job stuck in "Queued".** Here it means CodeBuild never picked the job up. Check the
project's build history in the AWS console. If no build started and the project and connection
are healthy, the webhook was dropped: cancel the run and re-run it (`gh run cancel <id>`, then
`gh run rerun <id>`). Re-running the same queued run does not help until it is cancelled. On
2026-10-30, jobs queued for 18 minutes to 10 hours, and each ran normally after a cancel and
re-run.

## Merge gate

Required contexts on `main` (API read-back, 2026-10-27): `gates`, `guard` and `pinned-demo` from
GitHub Actions (app 15368), and `verdict-gate` from the dedicated app `open-fleet-verdict-gate`
(app 5451539). Branches must be up to date (strict), admins are enforced, and every conversation
must be resolved. `pinned-demo` became required on 2026-10-23 so the demo gate the table above
names actually blocks. `verdict` is no longer required (#594); it still runs as fast feedback.
`Greptile Review` (app 867647) was required until 2026-10-27, when Greptile was removed.
No approving review is required: the owner is the only collaborator, and GitHub does not let an
author approve their own PR, so requiring one would block every merge.

Fork pull requests get no write token and no secret (API read-back, 2026-10-27). The repository
is public, and on a public repository GitHub never sends a write token or a secret to a workflow
run that a fork's pull request triggers, whatever the workflow's `permissions:` asks for.
`GET /repos/ravidsrk/open-fleet/actions/permissions/workflow` returned
`{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`: a run's
`GITHUB_TOKEN` is read-only unless its workflow asks for more, and it can never approve a pull
request. Re-read both with `gh api repos/ravidsrk/open-fleet --jq .visibility` and
`gh api repos/ravidsrk/open-fleet/actions/permissions/workflow`. If the repository ever goes
private, also read Settings → Actions → General → "Fork pull request workflows in private
repositories" (send write tokens, send secrets), which applies only then. So a fork PR's own
workflow can turn a required check green (below), but it cannot write `main`, a tag or a release.

The trusted check for a GO verdict is the `verdict-gate` commit status, posted by
[`verdict-gate.yml`](../.github/workflows/verdict-gate.yml). GitHub loads that workflow from
`main` on `workflow_run`, after every review that
[`verdict-check.yml`](../.github/workflows/verdict-check.yml) sees, and it runs `main`'s
`scripts/verdict_check.py`, so nothing a PR edits takes part in gating it. The `verdict` job in
`verdict-check.yml` still runs as fast feedback, but a review run loads that file from the PR,
where the PR can rewrite it.

**What a green `verdict-gate` proves.** A trusted account bound `VERDICT: GO` to this exact head
SHA: an APPROVED or COMMENTED review whose author's association is OWNER, MEMBER or
COLLABORATOR. The review state alone proves nothing, because on a public repository any account
can submit an APPROVED review (PR #718 review). The latest trusted verdict at the head decides:
a later CHANGES_REQUESTED or `VERDICT: NO-GO` from such an account at that head vetoes an
earlier GO, and a later GO clears it. And the PR changes no grader path unless the owner opened
it from a branch of this repository (below). Being the PR's author is no trust tier, so a fork
author's GO on their own PR never counts (2026-10-27 security audit, W6-06).

**CI runs the PR's code; the GO is the control.** Every required job runs code from the PR's own
tree: its tests, and whatever the gate scripts import. Code that runs inside a check can make
that check pass, so a green `gates`, `guard` or `pinned-demo` is not evidence about a PR the
owner did not write. For such a PR the merge control is the trusted GO bound to the exact head,
and that GO is the reviewer's attestation that they read the diff at that head. No check here can
verify the attestation, and with one human maintainer the owner's GO on their own PR is the
normal case. The rule below narrows the cheap ways to green a check; it does not make CI a
reviewer.

**A PR cannot change its own grader (W6-01).** `gates`, `guard` and `pinned-demo` come from
`pull_request` runs, which GitHub loads from the PR's merge ref, so the PR's own YAML decides
what those contexts run. A fork PR that empties the jobs (`steps: [{run: echo ok}]`) gets all
three green with every real gate skipped, and branch protection matches them by name only.
`verdict-gate` is the one required context whose code comes from `main`, so `main`'s
`scripts/verdict_check.py` also posts `verdict-gate` failure, whatever GO the PR has, when the PR
adds, edits, removes or renames a grader path. The one exception is the repository owner's PR
from a branch of this repository: the PR's `author_association` is `OWNER` (or its author is the
owner's login) and its head repository is this repository. An owner-opened PR whose head is a
fork's branch gets no exemption, because the fork keeps push access to that branch. The grader:
- `.github/workflows/`: every job, step, `needs:` and `if:` of the three build contexts, and
  `verdict-check.yml`, which wakes this gate. The directory itself, or `.github`, changed as a
  path of its own (a file or a symlink where the directory was) counts too.
- `.github/actions/`: a local action a workflow can `uses: ./.github/actions/…` (none today).
- `.github/ci-tools.lock`: which build of coverage, ruff and agentskills those jobs install and
  run. A PR could lock a package it published itself.
- The scripts a required job names on a `run:` line, each of which is a gate (PR #718 re-attack:
  a `shard-tests.py` that ran nothing, a `gate.py` that exited 0 and a `run.sh` that printed the
  pinned transcript each kept their check green): `scripts/shard-tests.py`, `validate.py`,
  `check_trailers.py`, `changelog.py`, `gen-badges.py`, `eval.py`, `bundle.py`,
  `runtime/scripts/decisions.py`, `proof_status.py`, `run_report.py`, `bench/vf-bench/gate.py`,
  `replay.py`, `heldout.py` and `evals/demo/negative-control/run.sh` (`GATE_SCRIPTS` in the
  script; `tests/test_verdict_check.py` holds the list to the workflows). `guard` runs the base
  branch's `floor_guard.py`, which no PR can edit.
- `tests/__init__.py`: every shard runs `-m unittest tests.<module>`, which would import it
  before any test, so it could rewrite the runner.
- A module file at the root (`*.py`, `*.pyc`, `*.pyd`, `*.so`, `*.pth`) or a top-level directory
  this repository does not have: `shard-tests.py` runs `python -m coverage` and `-m unittest`
  from the root, so a root `coverage/` or `unittest.py` would run instead of the locked tool.
  That invocation cannot be isolated (its `tests.<module>` ids need the root on `sys.path`);
  every tool module and inline script a workflow runs itself (`-m pip`, `-m unittest`, `-c`,
  `python3 -`) carries `-I`, so the checkout is not on its path at all.

What the gate scripts import, and the tests, are not on the list: a PR could not change any code
otherwise. They are what the GO above has to cover. The bar's own settings (`.coveragerc`,
`ruff.toml`, `.gitleaksignore`, `.gitleaks.toml`, the routing floor, the
vf-bench pins) are the floor guard's frozen surface, which `guard` checks with the base branch's
`floor_guard.py`. The gate reads what the PR's exact head changes with the compare API (base
branch `...` head SHA), so a head flipped between its reads cannot pass. Those reads use the
gate job's own `GITHUB_TOKEN` (Contents and Pull requests read); the app's token posts the
status. Every read is bounded: one that fails or gives no answer in 90 seconds is a failed read.
Only a failure before the gate knows the PR's head SHA (naming the PR, or the first read of it)
leaves no status, because there is no commit to post one on. After that, a list the API may have
cut short (300 files), a head that moves while it is read, or any failed read (the reviews, the
second read of the PR, the compare) fails closed: the gate posts `verdict-gate` failure saying
which. The owner's own-branch PR is the one exception, for the grader read alone: it is
recognised from the PR object the gate has already read and decided on its verdict, so a failing
or hung compare read can never block the owner's PR (the one that would fix the gate included;
admins are enforced on `main`). Its reviews must still be read: without them there is no
verdict, and the gate posts failure. An outside contributor's grader change lands when the
owner re-opens it from a branch of this repository. The rule binds only once it is on `main`:
the gate runs `main`'s copy of the script, so the PR that adds it is still graded by the copy it
replaces.

Activated on 2026-10-24 (#594):
- **The app:** `open-fleet-verdict-gate` (app 5451539) was created from a manifest with Commit
  statuses (write) and Pull requests (read), no webhook, and installed on this repository only.
- **The `verdict-gate` environment:** deployment is limited to the `main` branch. It holds the
  variable `VERDICT_GATE_CLIENT_ID` and the secret `VERDICT_GATE_PRIVATE_KEY`. The key went
  straight from GitHub's manifest conversion into the secret and was never printed or stored
  elsewhere.
- **Branch protection:** `main` requires `verdict-gate` with the app as its expected source and no
  longer requires `verdict`.

The disposable PR [#658](https://github.com/ravidsrk/open-fleet/pull/658) witnessed the switch;
it was never merged. The read-backs are in
[`594-verdict-gate-activation.txt`](completion/evidence/594-verdict-gate-activation.txt):
1. Its own job named `verdict-gate` and a `verdict-gate` status posted with `GITHUB_TOKEN`
   (both from app 15368) left it BLOCKED, with every other required check green and no open thread.
2. A GO review at its head made the app post `verdict-gate` success, and the PR turned CLEAN.
3. After a content-changing push, the app posted `verdict-gate` failure because no GO bound the
   new head ("GO verdicts exist but none binds the current head"), and the PR was BLOCKED again
   until a fresh review.

Branch protection matches a required check by name, and a fork PR can add a workflow job named
`verdict-gate`. The status must therefore come from an identity only `main`'s gate can use. To set
it up again, for example after rotating the key:

1. Create a GitHub App (Settings → Developer settings → GitHub Apps) with no webhook and two
   repository permissions: Commit statuses (read and write) and Pull requests (read-only).
   Install it on this repository only.
2. Create the environment `verdict-gate` (Settings → Environments) with deployment branches
   limited to `main`. Add variable `VERDICT_GATE_CLIENT_ID` (the app's client ID) and secret
   `VERDICT_GATE_PRIVATE_KEY` (a private key generated for the app) to that environment, not to
   the repository. A job on any other branch, whether a fork's or a writer's own branch
   workflow, never receives the key.
3. Post a review on any open PR so the gate runs once, then edit the `main` branch rule: require
   `verdict-gate` with the app as its expected source, and stop requiring `verdict`.

Until step 2, the gate posts as `github-actions` and its run log carries a warning saying so. To
re-evaluate a PR, post a review on it or re-run its latest `verdict-gate` run. The gate has no
manual-dispatch trigger, because a dispatch loads the workflow from whichever branch is picked.

**Second reviewer (#595).** On 2026-10-24 the owner designated OpenAI Codex as the independent
second reviewer (H-10 in [HUMAN_ACTIONS](completion/HUMAN_ACTIONS.md)).
- **How it runs:** Codex runs `codex exec -s read-only` in a clean detached checkout of the PR's
  head, with the repository's rules as its standard.
- **Where it posts:** its verdict is posted verbatim as a COMMENT review that ends with `VERDICT:`
  and the full `reviewed_sha`.
- **The rule:** the coordinator posts no GO of its own without a Codex GO at the same head, and a
  new head needs a new Codex review.
- **Its limit:** Codex is not a person, so the number of human maintainers is still one.

## Release cut

A release has two commits: the **cut** contains its version, dated changelog and a
`preparing` record; the later **provenance** commit records the cut SHA. Published
rows and historical tag targets remain immutable. A preparing version is not yet
published: green preparation checks validate all historical releases too.

Start on a clean release branch with full history and tags fetched. Set
`RELEASE_VERSION` to the next semantic version and `RELEASE_DATE` to its ISO date
(`export RELEASE_VERSION=0.6.2 RELEASE_DATE=2026-09-12`, for example).
Run each complete block in order. Its subshell stops on any failed command
without depending on error-handling options in your interactive shell.

### Prepare

The following changes the three version surfaces together and marks only the
newest heading as preparing. It also folds in the bookkeeping that pull requests
file one file per change, so that no two PRs edit a shared line: the
`changelog.d/` fragments become the dated `CHANGELOG.md` section and are deleted
([`changelog.d/README.md`](../changelog.d/README.md)), the tests badge takes
today's count (`gen-badges.py --release`; between releases it shows the last
release's count and the README badge says so), and the run index in
[`docs/runs/README.md`](runs/README.md) is re-rendered from `docs/runs/index/`.

<!-- release:prepare -->
```bash
(
set -eu
status=$(git status --porcelain)
test -z "$status"
python3 - <<'PY_RELEASE'
import json, os, re, subprocess, sys
from datetime import date
from pathlib import Path
version, day = os.environ["RELEASE_VERSION"], os.environ["RELEASE_DATE"]
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
assert date.fromisoformat(day).isoformat() == day
path = Path("docs/releases.json")
data = json.loads(path.read_text())
assert data.get("preparing") is None, "finish the current preparation first"
assert all(tuple(map(int, version.split("."))) > tuple(map(int, r["version"].split(".")))
           for r in data["releases"]), "choose a new version"
for tool in (["scripts/changelog.py", "assemble", version, day],
             ["scripts/gen-badges.py", "--release"],
             ["scripts/run_index.py", "write", "--as-of", day]):
    subprocess.run([sys.executable, *tool], check=True)
for name in ("plugin", "marketplace"):
    manifest = Path(f".claude-plugin/{name}.json")
    value = json.loads(manifest.read_text())
    if name == "plugin": value["version"] = version
    else:
        value["metadata"]["version"] = version
        value["plugins"][0]["version"] = version
    manifest.write_text(json.dumps(value, indent=2) + "\n")
data["preparing"] = {"version": version, "cut_date": day}
path.write_text(json.dumps(data, indent=2) + "\n")
PY_RELEASE
python3 -m unittest tests.test_docs_navigation.TestDocsNavigation tests.test_docs_navigation.EveryReleaseHasTheTagItDescribes
)
```

Run the repository gates, including `python3 scripts/validate.py`,
`python3 -m unittest discover -s tests` and the cut's bookkeeping checks
(`python3 scripts/changelog.py check --released`,
`python3 scripts/run_index.py check --current` and
`python3 scripts/gen-badges.py --check --release`, which `release_check.py`'s
`gate0/release-bookkeeping` runs once `preparing` is set), and review the diff
before the cut.
Every published heading still needs its commit and annotated tag; only the sole
newest preparing heading has no cut SHA. Green checks do not authorize publication.
`release_check.py`'s CI checks read the `validate` and `install` runs at exactly this branch's
HEAD and need the newest of each green, so push the branch and open its pull request first
([checklist](release-1.0-checklist.md), gates 0 and 4).

<!-- release:cut -->
```bash
(
set -eu
python3 -c 'import json, os; assert json.load(open("docs/releases.json"))["preparing"]["version"] == os.environ["RELEASE_VERSION"]'
git add CHANGELOG.md changelog.d .claude-plugin/plugin.json .claude-plugin/marketplace.json \
    docs/releases.json docs/assets/badges/tests.json docs/runs/README.md
git commit -m "Prepare release $RELEASE_VERSION"
)
```

### Tag and record provenance

The maintainer must authorize the exact cut SHA and version before creating or
publishing its tag. The remaining steps run only after that gate. A fixture
rehearsal may create local tags in its disposable repository without publication.

<!-- release:tag -->
```bash
(
set -eu
status=$(git status --porcelain)
test -z "$status"
python3 -c 'import json, os; assert json.load(open("docs/releases.json"))["preparing"]["version"] == os.environ["RELEASE_VERSION"]'
cut_sha=$(git rev-parse HEAD)
git tag -a "v$RELEASE_VERSION" "$cut_sha" -m "open-fleet $RELEASE_VERSION"
python3 -m unittest tests.test_docs_navigation.TestDocsNavigation tests.test_docs_navigation.EveryReleaseHasTheTagItDescribes
)
```

Record the existing cut in a **new commit**, keeping the cut and its tag unchanged.
The command rejects a missing tag, a lightweight tag, or a tag at another cut.
Keep `RELEASE_VERSION` set to the authorized version. The same block accepts
its exact recorded inventory on retry, including after the commit succeeded.

<!-- release:record -->
```bash
(
set -eu
python3 - <<'PY_RELEASE'
import json, os, subprocess
from pathlib import Path
def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()
path = Path("docs/releases.json")
data = json.loads(path.read_text())
tag = "v" + os.environ["RELEASE_VERSION"]
ref = "refs/tags/" + tag
assert git("cat-file", "-t", ref) == "tag", "an annotated tag is required"
cut = git("rev-parse", ref + "^{commit}")
git("merge-base", "--is-ancestor", cut, "HEAD")
# The cut is immutable, so it -- not the working tree -- says what this release records.
at_cut = json.loads(git("show", cut + ":docs/releases.json"))
pending = at_cut.get("preparing")
assert pending and pending["version"] == os.environ["RELEASE_VERSION"], "wrong release cut"
recorded = {**at_cut, "preparing": None,
            "releases": [*at_cut["releases"], {**pending, "tag": tag, "commit": cut}]}
assert data in (at_cut, recorded), "inventory differs from the cut or its exact provenance"
assert not git("status", "--porcelain", "--", ".", ":(exclude)docs/releases.json"), "unrelated changes"
git("diff", "--exit-code", cut, "--", "CHANGELOG.md", ".claude-plugin")
if data != recorded:
    path.write_text(json.dumps(recorded, indent=2) + "\n")
PY_RELEASE
python3 -m unittest tests.test_docs_navigation.TestDocsNavigation tests.test_docs_navigation.EveryReleaseHasTheTagItDescribes
git add docs/releases.json
changes=$(git diff --cached --name-only -- docs/releases.json)
if [ -n "$changes" ]; then
    git commit -m "Record release $RELEASE_VERSION provenance"
fi
)
```

Re-run the repository gates and review the provenance commit before publishing
the approved branch and the single approved tag (`git push origin "v$RELEASE_VERSION"`).
The published state requires `preparing: null` and a row naming the cut, not the
provenance commit. Fresh clones fetch full history and tags before checking it.
The executable rehearsal is `python3 -m unittest tests.test_docs_navigation.ReleaseCutWalkthrough`.

**Recovery:** fetch missing historical tags first; compare each annotated tag's
peeled commit with its existing row. A mismatch stops the release for maintainer
investigation. Preserve published rows and refs; correct a bad release with a new
version. If tagging succeeded but recording failed, resolve the reported Git or
validation error and rerun the entire record block with the same `RELEASE_VERSION`.
Leave the inventory and any staged provenance in place: the block validates them
against the existing tag's cut, completes an interrupted write/stage/commit sequence,
and makes no new commit if recording already succeeded. Investigate a lock's owner
before removing a stale lock; never delete an active process's lock. An inventory
that differs from both expected states stops for investigation. Do not amend the
cut, recreate its tag, or reset published mappings to make a retry pass.

## Publishing Releases

`.github/workflows/release.yml` publishes a GitHub Release with the version's CHANGELOG
section as notes on every `v*` tag push (idempotent; it never creates a tag — the tag is
the authorization step above). The historical tags that predate it got their Releases once,
by hand, from the maintainer's account (both publishers refuse any other actor, below); a
read-back on 2026-10-27 lists all thirteen, `v1.0.0` Latest. Runs are serialized (one running,
one pending; a third queued run cancels the pending one), so a backfill dispatches one tag and
waits for its run before the next:

```bash
for t in v0.1.0 v0.1.1 v0.2.0 v0.2.1 v0.3.0 v0.4.0 v0.5.0 v0.6.0 v0.6.1; do
  gh workflow run release.yml -f tag="$t"
  sleep 15   # let the run register before asking for it
  gh run watch --exit-status "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
done
gh release list --limit 20
```

A backfilled Release is published with `--latest=false`: only the newest `vX.Y.Z` tag the remote
holds, in version order and read just before publishing, takes GitHub's "Latest" (2026-10-27
security audit, W6-11; PR #718 review).

`.github/workflows/publish-dist.yml` builds `scripts/bundle.py`'s self-contained tree on the
same tag pushes (a manual run must name an existing `v*` tag; it refuses a branch) and
force-pushes it to the `dist` branch, the target copy installers point at
([docs/install.md](install.md)). Its staging step adds the tree with `git add -A --force`, so
a `.gitignore` a mission carries cannot drop a file, and it fails unless the index holds every
built file byte for byte, nothing else, and every entry of each mission's `bundle-files.json`
(W6-04).

Both publishers check the tag is `vMAJOR.MINOR.PATCH` before the checkout, and publish-dist
checks out that checked value, so a dispatch input is never fetched before it is validated
(W6-16).

Both publishers refuse to run unless the tag's commit is on `main` and the account that pushed
or dispatched, and the one that started the attempt, is the repository owner (2026-10-23
review, P2-23). That step lives in the workflow file at the tagged commit, so it binds only a
reviewed copy: a writer can tag a commit whose own copy drops it. What binds the tag itself is
a tag ruleset, a repository-settings change made only on the owner's word. In force since
2026-10-23 (ruleset 25710508, created on the owner's instruction): creating, moving and deleting
`v*` tags is restricted to the repository admin role, which on this personal repository is the
owner alone. To recreate it:

```bash
gh api --method POST repos/ravidsrk/open-fleet/rulesets --input - <<'JSON'
{
  "name": "release tags: maintainer only",
  "target": "tag",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
  "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
  "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
}
JSON
gh api repos/ravidsrk/open-fleet/rulesets   # read back: one active tag ruleset on refs/tags/v*
```

`actor_id` 5 is GitHub's built-in admin repository role. Neither step closes one path: a
writer's own branch workflow can request a `contents: write` run token and push `dist`
directly; closing that needs `dist` published with a credential only a tag-restricted
environment holds.

## Incident (2 a.m.)

1. A red `validate` or `negative-control-demo` run on `main` files (or updates) an issue labeled
   [`ci-failure`](https://github.com/ravidsrk/open-fleet/issues?q=label%3Aci-failure)
   — that issue is the alert; it arrives through normal issue
   notifications, not the opt-in Actions setting. Open the run it links —
   catalog gates (`scripts/validate.py`, `tests/`, `proof_status.py --check`)
   are the only environment; the run summary shows the proof rollup and
   routing score. Close the issue when `main` is green again. To prove the
   path without redding `main`: Actions → `alert-on-failure` → Run workflow
   (a `[drill]` issue is filed and closed by the same run).
   Two shapes that are NOT a red suite: a run whose jobs all ended within
   seconds with no steps and no runner (`runner_id: 0` in the API) is an
   Actions or account-level incident — re-run it, do not debug the tests;
   and when that happens the alert workflow could not run either (it needs
   the same runner), which is how 2026-09-23 and 2026-09-25 went red on
   `main` with nothing filed (#520). The daily `main-health` schedule
   re-reads the latest `validate` conclusion and files the issue when
   Actions is running but nothing was filed; the no-runner case needs a
   check outside Actions — an uptime monitor or a cron on your machine
   polling `gh run list --workflow validate.yml --branch main --event push --status completed --limit 1 --json conclusion,updatedAt`
   (the query `main-health` runs, so an in-progress run never pages) and
   paging you when the result is absent (no completed run), stale
   (`updatedAt` older than a day), or its conclusion is not `success`
   (#528). An hourly **open-fleet external CI monitor** heartbeat is configured in
   Codex on the maintainer's macOS host, outside Actions. Its `automation.toml` records it
   **ACTIVE** (2026-10-23), but no scheduled Codex firing has been observed (the automation
   directory holds no `health-state.json` and no Codex session ran it), so treat it as an
   unverified backup to the cloud task below. It
   uses [`scripts/external-ci-monitor.py`](../scripts/external-ci-monitor.py), installed
   at `~/.codex/automations/open-fleet-external-ci-monitor/external-ci-monitor.py`, and
   must be refreshed from a trusted, updated `main` checkout before activation and
   after any poller change. From that checkout, copy, compare, then query the installed copy:

   ```sh
   mkdir -p "$HOME/.codex/automations/open-fleet-external-ci-monitor"
   cp scripts/external-ci-monitor.py "$HOME/.codex/automations/open-fleet-external-ci-monitor/external-ci-monitor.py"
   cmp scripts/external-ci-monitor.py "$HOME/.codex/automations/open-fleet-external-ci-monitor/external-ci-monitor.py" && python3 "$HOME/.codex/automations/open-fleet-external-ci-monitor/external-ci-monitor.py"
   ```

   Record the matching script hash and result when refreshing. The heartbeat
   alerts in this chat, with a durable `ci-failure` issue when the GitHub API is reachable.
   It treats an absent run, a non-`success` conclusion, a success at least 24 hours old,
   and a failed API/authentication check as unhealthy. Healthy or unchanged results stay
   quiet; a new failure, meaningful change or recovery alerts the maintainer. The local
   host must be awake and Codex open; this is not an always-on hosted service.
   The [external drill](completion/evidence/T-13-external-monitor-drill.txt) detected the
   real no-runner outage from the local host and filed/closed
   [#537](https://github.com/ravidsrk/open-fleet/issues/537). That September drill proves the
   poller and durable-issue alert path; it claims neither email delivery nor a scheduled Codex
   heartbeat firing. The scheduled firing on record is the cloud task's, below, in the same
   receipt. The Codex heartbeat is the backup: it runs only while the Mac is awake.

   The always-on watch is a **Claude Code scheduled task**, "open-fleet main CI monitor"
   (claude.ai → Code → Scheduled tasks, on the maintainer's account), firing daily at
   13:17 UTC in a fresh cloud session. Nothing in it runs on a GitHub runner, so a
   no-runner outage cannot silence it. Each run clones `main` and runs the same poller with
   no CLI login: `python3 scripts/external-ci-monitor.py --transport rest --quiet-when-current`.
   `--transport rest` reads the public API (a `GITHUB_TOKEN`, when the host has one, is
   sent; the repository going private would need one). `--quiet-when-current` keeps a green
   run on `main`'s current head healthy past 24 hours, so a week with no merges does not
   page you, while a head that CI never finished still goes `stale`. A healthy run ends
   quietly. A `red`, `stale` or `missing` result, or a `monitor-error` (API down, or rate
   limited), ends the session with an `ALERT:` summary that reaches you by push
   notification and email. To drill it without touching `main`, fire the task with the
   text `DRILL: add --drill-run 36146072394` (the archived no-runner run the T-13 receipt
   uses). The task is routine `trig_01LHVNVyoRrPFtKPwYzTPBoP`, created 2026-10-23 with no
   connectors and only `Bash`/`Read`; its first scheduled firing ran at 2026-10-23T14:46:17Z
   (session `cse_015URvHfDuWv4mRggZg6JWCa`) and reported `healthy` for `main` `5fcab11`, recorded
   in the [T-13 receipt](completion/evidence/T-13-external-monitor-drill.txt) (#528). A routine
   still named "orca-fleet main CI monitor" is the pre-rename duplicate; delete it at
   claude.ai/code/routines.
2. If a clone or plugin load is broken: `plugin.json` `version` must equal
   the latest **dated** [CHANGELOG](../CHANGELOG.md) heading
   (`## [x.y.z] - YYYY-MM-DD`), not `[Unreleased]`. Do not half-cut a
   version bump.
3. Secrets never live in git (`.env`, `.secrets/` are ignored). Dispatch-key
   rotation must update **all three** verifier sources
   ([docs/verify-gate.md](verify-gate.md)):
   unset `ORCA_DISPATCH_PUBKEY`, land a new `.orca/dispatch-pubkey` through a
   reviewed PR, then on every verifier clone `git fetch origin` and confirm
   `git show origin/HEAD:.orca/dispatch-pubkey` equals the newly merged
   `.pub` (an unchecked fetch can leave the old pin). Do not leave a stale
   working-tree copy. Generate the pair with
   `runtime/scripts/dispatch-sign.py gen-key` **off the clone**; discard the
   old private seed. Security reports follow [SECURITY.md](../.github/SECURITY.md).
4. Rollback = `git revert -m 1 <merge-sha>` on a branch, then a PR
   through the normal gates — never a force-push or a history rewrite
   on `main`. There is no hosted service or staging environment. A merge
   to `main` is the "deploy" above: it changes the default-branch tree that
   clones install; the marketplace installs the `dist` branch (`"ref": "dist"`). Versioned
   publication is separate — `release.yml` (the GitHub Release) and
   `publish-dist.yml` (the `dist` branch) run on a `v*` tag push or a
   manual run naming an existing tag, and a tag exists only for an exact
   cut the maintainer authorized (Tag and record provenance, above). So an
   untagged bad merge is undone by the revert alone; a published bad
   release is never re-tagged or deleted — revert on `main`, then publish
   a new version through that same authorization, whose tag re-runs both
   workflows. A bad merge is undone the way it landed. Regenerate badges
   (`python3 scripts/gen-badges.py`) if the revert changes counts.
   Rehearsed on a scratch clone: 2026-09-01
   ([transcript](completion/evidence/P0-rollback-rehearsal.txt)) and
   2026-09-02
   ([transcript](completion/evidence/P0-r2-rollback-rehearsal.txt))
   (both single-parent reverts), plus the 2026-09-02 merge-shaped rehearsal
   ([transcript](completion/evidence/T-12-rollback-merge-rehearsal.txt) —
   it also shows the plain `git revert <merge-sha>` failure mode).
   If a deploy target ever appears, this step gains a staging deploy →
   rollback rehearsal and the completion register re-opens G-14 under P4.
