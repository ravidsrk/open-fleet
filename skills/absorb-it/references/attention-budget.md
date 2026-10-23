# Runtime policy — attention budget (orchestration tax)

Starting agents is cheap; closing the loop is not. Human judgment is the serial bottleneck
(Amdahl / GIL of the fleet). Scale the fleet to **verification capacity**, not the UI's spawn
limit. Merge serialization (`merge-serialization.md`) is consumer-side backpressure; this policy
is producer-side.

## WIP caps (defaults — ASSERTED; no protocol-compliant measurement yet; override in the ledger header when measured)

| Class | Concurrent builders | Concurrent build-blind reviewers | Notes |
|-------|---------------------|----------------------------------|-------|
| Mutation wave (ship / sweep / harden / …) | ≤ 3 | ≤ 1 per 3 builders (min 1) | Match the review rate; the reviewer cap counts review UNITS in flight — each unit's acceptance-review fans to its ≤3 isolated axis workers, which are exempt |
| Report-only (review-it axes) | n/a | ≤ 4 axis workers | Axes stay isolated; cap total terminals |
| Planning (map-it research) | ≤ 3 research workers | n/a | Decision tickets stay one-at-a-time HITL |

`WIP: builders=<n> reviewers=<n>` is a required ledger-header field, written at T0 with the
wave plan sized to it (liveness-resume.md) — a cap recorded nowhere was never a cap. Exceeding
it → hold the next dispatch until a unit leaves `dispatched` (verify or park), never silently
raise it.

The cap counts live PANES, not tasks (builders); for reviewers it counts review UNITS in flight —
a unit's build-blind acceptance-review fans to its isolated axis workers, and that fan-out is ONE
review unit, not N against the reviewer cap: a doctor respawn's original pane counts against the cap
until its closure is verified by pane read. Heartbeat false negatives spawn dual writers — the
2026-07-15 chimely run planned a 4-builder wave and peaked at 5 builder panes this way — a recalled
post-mortem, not a retained report. That mechanism no longer applies: liveness now comes
from `worker-list`'s `projection.liveness` and `attention.requiresAction`, not from reading panes
for heartbeats (liveness-resume.md).

Evidence level: **ASSERTED.** The defaults were first asserted from one field run (2026-07-15
chimely) and its dual-writer post-mortem; no published methodology for sizing fleet concurrency to
verification capacity exists anywhere yet. The 2026-08-28 ship-it self-run
(`docs/runs/2026-08-28-ship-it-self-run.md`) is recorded but is **not a protocol-compliant data
point** and does **not** count toward the ≥3-run threshold below — not because it ran at
`builders=1` (a legitimate low-WIP setting the curve needs), but because it reached verified-BUILT
rather than the protocol's unit of throughput (units reaching verified-CLOSED per hour): it produced
no CLOSED-throughput figure to plot. What it shows is narrow and qualitative — in a *solo* run the
independent-review/approval step is what blocks *autonomous completion* of a mutation unit (the
hardened verifier `verify.py` requires an independent approval it cannot self-issue). That is a
statement about the completion gate, not a throughput measurement: the wall-clock was dominated by
building and acceptance review, machine verification took seconds, and a single non-parallel unit
cannot by itself locate a throughput bottleneck. The caps stay ASSERTED until ≥3 runs at differing
WIP settings (a `builders=1` run counts) measure verified-CLOSED-per-hour throughput (protocol below).

## Sort the work (do not parallelize judgment)

- **Isolated / machine-verifiable** → background workers (clean-sweep findings, slice builds with
  clear ACs, characterization tests).
- **Judgment-heavy** → serial on the coordinator or a dedicated interactive session (architecture
  forks, foggy diagnosis, one-way product calls). Parallelizing these thrashing the lock.

## Spend the lock only on judgment

Mechanical proof (tests, negative controls, ancestry, reviewed-SHA) is machine-checked via
`evidence-manifest.md`. Batch one-way human gates when several park at once — context-switch cost
dominates. Never spawn more agents to feel busy; throughput equals review+verify throughput.
There is no CLI pre-wave usage signal: rate-limit windows (5h/7d) exist only as shared types
(`rate-limit-types.ts`), and `account list` renders no usage numbers (`account.ts:300-310`). Size
the wave to the recorded WIP cap, not to a quota check — the quota check does not exist.

## The WIP-curve protocol (how a cap graduates from asserted to measured)

Every mutating fleet run from 2026-08-28 forward records one row per dispatch wave in its `docs/runs/` report, checked
by `run_report.py` (#365, #389): its waves are `1`…`<n>` of the `RUN:` header's `waves=<n>`, each with exactly one table
row carrying every Row cell below (metric values digit-led). The rows are read only
under an ATX heading whose text begins `WIP-curve protocol row` as whole words (docs/runs/TEMPLATE.md), up to the next
heading and outside fenced code; a row anywhere else — a fenced example, a deviations table, a look-alike heading — is
not read (#387). Anything less does not bind.

| Metric | Row cell | Definition |
|---|---|---|
| Wave | `wave=<k>` | `1`…`<n>` |
| WIP setting | `builders=<n> reviewers=<n>` | the ledger-header `WIP:` it ran at |
| Builder throughput | `throughput=<v>` | units reaching verified CLOSED per hour of wave wall-clock |
| Verification latency | `latency_median=<v> latency_max=<v>` | median and max `worker_done` → verified-or-parked, per unit |
| Rework rate | `rework=<v>` | share of units bounced by evidence-manifest.md §2 (re-dispatch / SUSPECT) |
| Freshness violations | `freshness=<v>` | reviews voided by `reviewed_sha != head_sha` (reviewed-sha-freshness.md) |

After ≥3 runs at differing WIP settings, plot throughput and rework against WIP and revise the
caps table citing the run reports. Negative data counts — "cap 4 broke review freshness twice"
is a publishable point. A cap revised without a cited report is still ASSERTED.

## Completion

Every dispatch wave respects the recorded WIP; judgment-heavy units are not fanned; the run
report names any WIP override and why, and carries the WIP-curve protocol's per-wave rows.
