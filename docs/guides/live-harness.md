# Run a paid live arm in the container harness

Every paid live experiment arm runs one way: inside a fresh, disposable Linux container that
[`scripts/live_container.py`](../../scripts/live_container.py) starts, watches and destroys,
beside a credential broker in a container of its own. On a plain host every paid live path
refuses, exit 2, before it reads or reserves anything
([`containment.py`](../runtime-scripts.md#containmentpy)). This page is for the operator who runs
one. It covers building the image, supplying the token, the command for each arm, and what the
receipt proves.

The arms are `wip_curve` (#604), `ablation` (#606), `hint_replay` (#605), `trajectories` (#602) and
`first_run` (#596). Each spends money. Run one only under the spend its owner authorised: that
cap goes to the broker as `--cap-usd`, and to the arm's own cap flags.

## Why a container

A paid call's processes are found by the `OF_CALL_ID` marker in their environment, so a sweep can
end every one of them, a detached descendant included. On macOS that cannot be proven: `ps -E`
does not show an Apple system binary's environment (`/bin/sh`, `/bin/sleep`), so a shell a worker
detached is invisible. Inside a Linux container `/proc/<pid>/environ` shows every process, so the
strong containment probe passes. Destroying the container is the final backstop. It also ends a
process that escaped in-process containment, including one that cleared its own environment.

## Why a broker

The arm's container runs the agents as uid 10001, and every test those agents write runs as the
same user. A token mounted there would be readable by any of them, copied, or used for calls no
ledger records. So the token never enters the arm's container. It is mounted into the broker's
container, which runs [`scripts/live_broker.py`](../../scripts/live_broker.py) and nothing else.
The arm's container shares the broker's network namespace and nothing more: no file, process or
environment of it. Sharing the namespace shares its route out too, so the arm can open its own
connections to any host without passing through the broker: the broker caps and records model
calls, which need the token, and is not an egress control for anything else.

Inside the arm's container, `claude` on `PATH` is
[`scripts/live_container_bin/claude`](../../scripts/live_container_bin/claude). It waits for the
broker, then execs the pinned Claude Code with `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` and a
placeholder credential, dropping any credential, endpoint or proxy the arm's environment carries.
The broker forwards `POST /v1/messages` and `/v1/messages/count_tokens` to the API with the token
in place of the placeholder. It refuses every other request. It also refuses any call it cannot
price. A call passes only when its model is on the broker's price list, it carries a positive
`max_tokens`, every field is one the broker prices, and every tool is the client's own, wherever
it is defined: in `tools`, or inside a message. Its content must also be inline and bounded by its
bytes. So the broker refuses an image or document
by URL or file id, a PDF, an advisor or other server-side tool, an MCP server, server-side
compaction, a service tier, and an inference geography other than global or US. Each is billed
beyond what the request's bytes bound.

**The cap.** A call starts only when the broker's settled spend, the reservations of the calls in
flight and the call's own reservation fit under `--cap-usd`. A reservation is the call's worst
case: every byte of its body as a 1-hour cache-write input token, plus 4,096 tokens of framing and
4,800 for each inline image, and all of its `max_tokens` as output, at its model's highest list
price, times 2 for fast mode and 1.1 for US inference. A request that names no geography runs in
your workspace's default, which may be US, so it reserves at the 1.1 premium. Each call settles at
the geography the API reports it ran in, and at the premium when the API reports none. When the call ends, the
broker settles the usage the API reported, at the price the API bills. A call that ends without a
complete usage report settles its whole reservation. A refused call reaches the arm as an API
error (`permission_error`, "the spend cap … would be passed"). Near the cap, reservations stop
calls before the settled spend reaches it. Set each arm's own cap flag at or below `--cap-usd`,
so the arm stops itself first.

The broker prices at the Claude API's list prices of 2026-10-06. On the live smoke call, the
broker settled Haiku 5.5 at $0.000904, and Claude Code reported $0.00090427 for the same call.

## What the harness guarantees, and what it does not

The launcher starts both containers with these properties:

- the arm runs as the image's non-root user (uid 10001), and the broker as you: your own uid and
  gid, so it can read your 0600 token file and write its ledger on any Docker host. The launcher
  refuses to run as root. Each has `--rm`, a pids limit, a memory limit (no swap above it) and a
  CPU limit. The arm's limits are yours to set; the broker's are fixed (64 pids, 512 MB, one CPU);
- each has no capability (`--cap-drop ALL`), `no-new-privileges`, no `--privileged`, no host
  namespace, no published port, no device and no docker socket;
- the token reaches only the broker: your token file, which may not sit inside the results or
  the checkout, since the arm's container mounts both, mounted read-only at
  `/run/secrets/claude_token`. It is never in either container's environment, so `docker inspect`
  does not show it. It is never on a command line, in the receipt or in the saved output either.
  The output passes a redactor before it reaches the disk, so any occurrence is replaced with
  `[REDACTED]` and counted. The log is created mode 0600;
- both see `/repo`, a read-only, self-contained export of your checkout's `HEAD`. The launcher
  refuses a dirty tree, so the containers run a commit. Nothing they write reaches your checkout,
  its `.git` or its ignored files, such as a `.env`;
- the arm sees `/results`, its one read-write directory, which is also its working directory. Its
  own ledger and evidence outlive the container there. **Every output flag must name a path under
  `/results`**: `--results` and `--out` for `wip_curve`, `--out` for `ablation`, `hint_replay` and
  `trajectories`, and `--workdir` for `first_run`. The launcher refuses any other path, and an
  abbreviation of one of those flags counts as that flag. `ablation`, `hint_replay` and
  `trajectories` must also name an `--out`, and `first_run` a `--workdir`, because each one's
  default is a temp dir that dies with the container;
- the broker writes its ledger beside the receipt, out of the arm's reach: one JSON line when it
  opens, one for each call it starts and settles, and a counted `refuse` line per kind of refusal
  (path, terms, cap, count_tokens) at most once a second, its text cut short, since it quotes what
  the arm sent; the receipt's `refused` is the count. It never holds the token, a request or a
  response. Its container keeps no log, so a fault in the broker is a `fault` line here (the
  exception's type and frames only), and a call whose usage it cannot price settles its whole
  reservation. `count_tokens` is free but bounded (5,000 calls, 2 GiB of bodies per launch), with
  a running tally every 100 calls and on every later line. A connection that sends nothing is cut
  off after 60 s, its request line and headers must arrive within 30 s in all and its body within
  120 s (a byte at a time extends neither), and at most 32 are served at once. When all 32 are
  taken, a new connection evicts the one that has waited longest for its own request to arrive,
  so connections trickling requests, however many a process reopens, never keep the arm's own
  model calls out; a call already read in full keeps its slot. Every wait before a request is read
  in full -- for its headers, its body's first byte, its share of the body budget below, its body --
  ends at once when it is evicted, so an evicted connection's slot is free at once. A request body
  gets its share of that budget only once its first byte is here, and one whose bytes then arrive
  slower than 1 MiB/s (after a second's grace) is stalled: a request waiting for budget takes back,
  for itself, what a stalled body holds and evicts it at once, then waits for that body's buffer to
  come back (5 s past its own deadline at most), so stalled requests, however many arrive,
  cannot keep an ordinary call's body out. A request body is at most 32 MB (the
  API's own limit) and held once, and what the bodies take together -- their bytes and the most
  parsing them can allocate -- is at most 400 MiB (`BODY_BUDGET`), which leaves the interpreter and
  its parse children room in the broker's 512m. Before a body is read, the most one of its length
  can take parsed -- 13 times its bytes: the body, the string `json.loads` decodes it to, and the
  strings parsed out of it, the last two at up to four bytes a character (one emoji widens a whole
  string) and the last held twice over while the parser builds it -- is taken from that budget,
  and a request waiting for it holds none. A pre-scan of the bytes then bounds the parse more
  closely (each character at the width the body's widest character, or a `\u` escape, gives it;
  each JSON value at its worst parsed size): what the bound does not need goes back, and a body
  whose JSON values need more than its first share takes the difference then. Only one body read
  in full at a time may wait for that difference while holding its share; any other whose
  difference does not fit at once is answered 503 at once and gives back all of its share but its
  bytes', and while one waits every other take leaves room for what it needs, so no request ever
  waits for a share another waiting request holds. Once the parse is over, the body keeps only
  its bytes' share while it is relayed. However a request ends -- answered, refused, or with an
  exception -- its bytes' share goes back only once its buffer has been freed. The pre-scan holds no memory of its own (it finds one structural byte at a time
  and skips each string with a plain search, whatever escapes it holds) and stops after two million
  steps. The body is parsed in a child process whose memory limit is that bound, so a parse that
  would pass it fails there, never in the broker, which holds no parsed body. A budget take waits
  up to 30 s for room and is otherwise answered 503 (a `body-budget` refusal); a body whose bound
  alone could pass the budget, that nests more than 128 deep, whose pre-scan would pass its steps,
  or whose parse passes its bound, is answered 413 (a `body-parse` refusal). Ordinary requests --
  long or non-ASCII text, base64 images, thousands of messages, many tools, and a 32 MB request
  that is all ASCII but for one emoji -- pass.
  Every connection closed unanswered
  (evicted, past the bound, timed out, malformed, a body cut short) is counted as a `drop`. Drops
  and faults are counted per kind and written at most once a second per kind, with the running
  counts on every line and a `tally` line a second after the last one not written, so a client
  resetting connections in a loop cannot grow this file without bound;
- the arm sees the launcher's attestation, read-only. The attestation holds a fresh nonce, the
  commit, the arm, the image and the host's name, hashed (`host_sha256`), which names the machine
  across launches. The broker's container has the hostname `of-live-<nonce>`, and the arm's
  container inherits it with the network namespace. The receipt records the same nonce;
- one launch runs at a time. A launch holds `~/of-live/live-harness.lock` from its check for
  leftover containers until its receipt is written;
- it runs under a wall-clock limit. At the limit the launcher kills and removes both containers,
  then checks with `docker ps -a --filter label=org.open-fleet.live-harness=<nonce>` that neither
  exists. A docker call that fails or times out during the teardown is recorded in the receipt,
  and the remaining steps still run, so the receipt is always written. An in-container `timeout`
  120 s past the limit is the backstop if the launcher itself dies.

Inside the arm's container a paid entry point lifts its refusal only when three facts hold
(`containment.harness_problem`): a container marker (`/.dockerenv` or `/run/.containerenv`), an
attestation whose nonce matches the container's own hostname, and a passing strong probe. No
environment variable or flag lifts it. On any host without those facts every live path refuses
as before.

**The limit.** This guards against accidents on the host. It does not guard against an operator
who deliberately fakes a container. With root, anyone can write a `/.dockerenv`, an attestation
and a matching hostname on a Linux host. The attestation ties a container to its launch and
receipt; it is not proof against an adversary. Network egress is not restricted: the arm's tools
can reach the internet, but no process of the arm holds a credential, and every model call goes
through the broker's cap.

## Before you start

- **OrbStack** on macOS, or Docker Engine on Linux. The broker runs as you, so it reads your
  token file and writes its ledger on either. The arm runs as uid 10001 and must be able to write
  the results directory. On OrbStack a bind mount shows its files as owned by the container's
  user, so it can. On Docker Engine on Linux, give uid 10001 write access to the results directory
  (for example `setfacl -m u:10001:rwx <results>`).
- A **clean checkout** at the commit you mean to run. `git status` must show nothing, untracked
  files included.
- The arm's **authorised cap**, for `--cap-usd` and for the arm's own cap flags.

## 1. Build the image

```bash
python3 scripts/live_container.py build
```

This builds `open-fleet-live:claude-2.1.304` from
[`scripts/live_container.Dockerfile`](../../scripts/live_container.Dockerfile). The base,
`python:3.13.15-slim`, is pinned by digest. The image adds git, and installs Claude Code 2.1.304
with its official installer as the non-root user. The installer is saved to a file and runs only
when its sha256 is the pinned one, and the build fails unless the installed binary has the sha256
the 2.1.304 release manifest gives for the platform (x86_64 or aarch64) and reports that version.
A version bump re-pins both digests. The apt packages (git, curl, certificates) are the base's
distribution's current ones, not pinned. This is
the only step that downloads anything. The build refuses unless the Dockerfile on disk is
byte for byte the one your checkout's HEAD commits (read from the git object, not the working copy),
before docker reads it and after; commit an edit before you build. The image carries that committed
Dockerfile's sha256 as a label, and the build records the image ID it produced (the one docker writes to its `--iidfile`, never what
the tag names once the build is over), with that sha256, in `~/of-live/images.json`, outside the
image. A launch refuses an image whose ID this launcher's build did not record from the
committed Dockerfile, or whose label differs, where the committed Dockerfile is the one the commit
being run holds (its git object; an edit hidden from the dirty check changes nothing), unless you pass `--allow-foreign-image`; the receipt
records all three (`built_by_this_launcher`, `from_committed_dockerfile`, `foreign_image_allowed`).
The label alone is not enough: docker copies it into any image built `FROM` this one. Both checks
guard against accidents, a stale or derived image run by mistake. Anyone who can run docker is
root-equivalent and can forge either, so they are not a check against that person, and neither is
a check of the image's contents. Both containers run this image.

## 2. Store the token

```bash
mkdir -p ~/of-live && claude setup-token    # copy the token it prints
install -m 600 /dev/null ~/of-live/oauth-token && $EDITOR ~/of-live/oauth-token
```

The file holds the token alone, on one line. The launcher refuses a missing file, a file others can
read, a symbolic link, and an empty file, and it never prints the file's contents. Use
`--token-file` for another path. The launcher mounts this file, read-only, into each broker
container it starts; nothing copies it anywhere else.

## 3. Run one arm

Each command has the same shape:

```bash
python3 scripts/live_container.py run --arm <arm> --results <host dir> --timeout <seconds> --cap-usd <authorised USD> -- <the arm's own arguments>
```

Inside the container the repository is `/repo` and `<host dir>` is `/results`, the working
directory. Anything written outside `/results` is destroyed with the container. A command that
names a script runs it as `/repo/scripts/...`. Pass `--harness-version "2.1.304 (Claude Code)"`
where an arm asks for one: that is the container's harness, not your host's. Name models by an id
the broker prices (`claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`, or an alias Claude
Code resolves to one).

**wip_curve** (#604, [pre-registration](../experiments/wip-curve-prereg.md)). Run one scheduled run
per launch, then report inside the harness as well. The report re-runs worker-written oracles.
Both name the current registration, version 2, by its path in the container; a version has its own
results directory:

```bash
python3 scripts/live_container.py run --arm wip_curve --results ~/of-live/wip-curve-v2 --timeout 14400 --cap-usd <authorised> \
  --per-call-usd 1.60 -- --prereg /repo/docs/experiments/wip-curve-prereg-v2.json \
  run --results /results/experiment --workdir /results/sandboxes --worker live --agent claude \
  --model <pinned model id> --cost-cap-usd <the authorised cap> \
  --reservation-usd <the authorised reservation> --next 1
python3 scripts/live_container.py run --arm wip_curve --results ~/of-live/wip-curve-v2 --timeout 3600 --cap-usd <authorised> -- \
  --prereg /repo/docs/experiments/wip-curve-prereg-v2.json report --results /results/experiment
```

A run the API refused a call of for its credential (an expired token) ends `failed`
(`credential-rejected`). Replace the token file, then re-run it once as `<run id>-a2` with `--runs`.

`--per-call-usd 1.60` is the registration's per-call limit: every `claude` call the arm makes
carries `--max-budget-usd 1.60`, as the owner's isolation wrapper passed it on the host. The
launcher writes it to a read-only settings file in the arm's container, and the in-container
`claude` puts it before the arguments of each call that does not pass its own. Any arm can take `--per-call-usd`;
`hint_replay` passes its own limit with `--agent-limit-flag`, which the wrapper leaves alone.

**ablation** (#606, [pre-registration](../experiments/ablation-prereg.md)):

```bash
python3 scripts/live_container.py run --arm ablation --results ~/of-live/ablation --timeout 43200 --cap-usd <authorised> -- \
  run --tier live --cost-cap-usd <authorised> --model <model id> --harness-version "2.1.304 (Claude Code)" \
  --harness-cmd 'claude -p --output-format stream-json --permission-mode acceptEdits' --out /results/out
```

For #602's trajectory cells, use
`--harness-cmd 'python3 /repo/scripts/trajectory_harness.py claude -p --verbose --output-format stream-json --permission-mode acceptEdits'`.

**hint_replay** (#605, [`hint_provenance.py`](../runtime-scripts.md#hint_provenancepy)):

```bash
python3 scripts/live_container.py run --arm hint_replay --results ~/of-live/hint-replay --timeout 7200 --cap-usd 40 -- \
  --live --tier live --model sonnet \
  --agent-cmd 'claude -p --model sonnet --output-format json --permission-mode acceptEdits' \
  --budget-usd 40 --per-call-usd 2 --agent-limit-flag=--max-budget-usd \
  --max-runs 18 --attempts 3 --out /results/results.json
```

**trajectories** (#602, [adversarial evals](../adversarial-evals.md#running-the-live-arm)). The
launcher supplies `run --suite trajectories`:

```bash
python3 scripts/live_container.py run --arm trajectories --results ~/of-live/trajectories --timeout 14400 --cap-usd <authorised> -- \
  --tier live --all-live \
  --agent-cmd 'claude -p --verbose --output-format stream-json --disallowedTools TodoWrite,Task,WebFetch,WebSearch,NotebookEdit' \
  --model <exact model id> --harness-version "2.1.304 (Claude Code)" \
  --cost-cap-usd <authorised USD> --repeats 5 --out /results/out
```

**first_run** (#596, [certification](../certification.md)). It has no spend guard of its own, so
the broker's `--cap-usd` is its cap. Its `--json` receipt goes to the launcher's saved output, and
its `receipt.json` goes to the `--workdir`:

```bash
python3 scripts/live_container.py run --arm first_run --results ~/of-live/first-run --timeout 3600 --cap-usd <authorised> -- \
  run --worker live --agent claude --profile ro --keep --workdir /results/ro --json
```

To check the setup without spending, run an inert or fixture tier the same way, for example
`--arm first_run --cap-usd 1 -- run --worker inert --workdir /results/inert`.

`--pids-limit` (default 4096), `--memory` (8g) and `--cpus` (4) set the arm's limits. `--receipts`
(default `~/of-live/receipts`) sets where receipts and broker ledgers go. It may not overlap the
results or the checkout: the arm's container can write to the results, and the receipt and the
broker's ledger must stay out of its reach.

## 4. Read the receipt

Each launch writes `<receipts>/<UTC stamp>-<arm>-<nonce prefix>.json`. Beside it are the arm's
output as `.log` and the broker's ledger in `.broker/spend.jsonl`. The receipt holds:

| Field | What it records |
|---|---|
| `arm`, `arm_args`, `argv` | The arm, your arguments, and the exact command the container ran |
| `commit` | The checkout's `HEAD`, which `/repo` held |
| `image` | The image's id and digests, its labels, `built_by_this_launcher`, `from_committed_dockerfile`, and `foreign_image_allowed` |
| `nonce`, `hostname` | The attestation's nonce, and the hostname derived from it |
| `container` | The arm's container: its id, user, limits and mounts |
| `broker` | The broker's container, its cap, and `spend`: calls started, refused and settled, the settled USD, and any call still open when it was destroyed with its reservation |
| `started_at`, `ended_at`, `elapsed_s`, `wall_clock_limit_s` | When it ran, against the limit |
| `timed_out`, `interrupted`, `refused`, `exit_status` | How it ended: the limit, a signal, a refused start after a container was created, or the arm's own exit |
| `destroyed` | `verified: true` only when `docker ps -a --filter label=…=<nonce>` lists nothing; `errors` lists every teardown step that failed to run or timed out, and `nonzero` every one that exited nonzero (a container `--rm` already removed answers that way too) |
| `per_call_usd` | The per-call limit configured for the arm's `claude` calls, or null. A call that passes its own `--max-budget-usd` keeps that one |
| `token`, `token_redactions` | The token file's path and where the broker mounted it (never its value), and how many times the output carried it |

The receipt proves that one arm ran at that commit, in that image, in containers that no longer
exist, and what the broker let it spend. It does not prove the arm's result. That is the arm's
own evidence under `/results`, a `live-unreviewed` tier until a maintainer binds it in a run report
under [`docs/runs/`](../runs/README.md).

The launcher's exit is the arm's exit status once both containers are verified destroyed. It
exits 2 for a refused start, after destroying whatever it created. It exits 3 when a container
could not be verified destroyed (fail closed: run `docker ps -a --filter
label=org.open-fleet.live-harness`), and 124 when the limit ended the run.

## When it refuses

| Message | Fix |
|---|---|
| `the checkout … is dirty` | Commit or remove the listed paths |
| `no image …: build it first` | Run step 1 |
| `the image … was not built by this launcher from the committed Dockerfile` | Run step 1 at this commit, or pass `--allow-foreign-image` to run it anyway |
| `… holds a comma, a quote or a line break, which a docker --mount cannot carry` | Rename the path; for a staging path, point `TMPDIR` at a directory without one |
| `another launch holds …live-harness.lock` | One arm runs at a time. Wait for the other launch to end |
| `a harness container already exists` | A launch left one behind. Inspect the leftover, then `docker rm -f` it |
| `the token file … is readable by others` | `chmod 600` the file |
| `the <arm> arm needs --out under /results` (`--workdir` for `first_run`) | Name an `--out` (`first_run`: a `--workdir`) under `/results` |
| `--out … is outside /results` | Write every output under `/results` |
| `--cap-usd must be a positive number of dollars` | Pass the arm's authorised cap |
| `--token-file … is inside --results` (or the checkout) | Keep the token file outside both: the arm's container mounts them |
| `the broker never answered` | The broker could not start: it could not open the token file or its ledger, or the image is broken |
| `run the launcher as yourself, not root` | The broker runs as the launcher's user. Run the launcher as an ordinary user |
| `claude (open-fleet live harness): no credential broker answers` | `claude` ran in a container this launcher did not start |
| `open-fleet live broker: …is billed beyond…` (or `…not priced`) | The arm sent content, a tool or a field the broker cannot price. It refuses rather than spend unmetered |
| `open-fleet live broker: the spend cap ($…) would be passed` | The arm reached `--cap-usd`. The receipt's `broker.spend` shows what it settled |
| `open-fleet live broker: no price for model …` | Name a model the broker prices |
| `--receipts … overlaps --results` | Put the receipts outside the results |
| `live runs are disabled outside the container-based live harness` | You ran an arm directly on the host. Run it through this launcher |
