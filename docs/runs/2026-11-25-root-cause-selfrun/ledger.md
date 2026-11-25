# Root-Cause Diagnosis Ledger — `root-cause-2026-11-25-hidepid`

`RUN 2026-11-25-root-cause-selfrun · COORDINATOR open-fleet · BASE=- · FORK_POINT=- · T0 2026-11-25T17:06:00Z · SOURCE tests/test_spawn_worker.py parent-profile cap failure @ cfa3bd63 · WIP builders=0 reviewers=1`

| Hypothesis | Rank | Probe Artifact | Outcome |
|---|---|---|---|
| **H1** — `/proc` `hidepid=invisible` hides supervisor ancestor (`ppid > 1`, `stat(ppid) is None`), so `whoami()` (`allow_hidden=not live`) raises `Unknown` at `spawn_identity.py:196` once `reg.live_roots()` is non-empty | 1 | `repro-red.txt`, `falsification-probes.txt`, `diagnosis-evidence.md` | **SURVIVES (DEMONSTRATED)** |
| **H2** — `own_proc()` PID-namespace mismatch | 2 | `falsification-probes.txt` (Probe H2) | **FALSIFIED** |
| **H3** — `python3 -I` CLI, `setsid`, or `Registry` read/write/entries failure | 3 | `falsification-probes.txt` (Probe H3) | **FALSIFIED** |
| **H4** — `_uids(pid)` `/proc/<pid>/status` parsing failure | 4 | `falsification-probes.txt` (Probe H4) | **FALSIFIED** |

## Terminal Verdict

**`DIAGNOSED-WITH-HANDOFF`** — zero production or test code modified. Durable, path-free `agent-brief` handoff archived in `handoff-brief.md` with sound transitive shared-hidden-parent invariant across both active and UID-home registries plus 4 fail-closed negative controls; independent build-blind review **GO** (Round 3 of 3, `review.txt`).
