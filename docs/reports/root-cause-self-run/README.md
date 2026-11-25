# root-cause — Linux hidepid=invisible self-run summary envelope (2026-11-25)

**Bindable core:** [`docs/runs/2026-11-25-root-cause-self-run.md`](../../runs/2026-11-25-root-cause-self-run.md) (`inventory_at=60d93e1f42b43f5c0fdd460cdcc9f5326faa3439`, `verifier=GREEN`).  
**Terminal outcome:** `DIAGNOSED-WITH-HANDOFF` (planning / diagnosis-only class; zero production or test code modified).

## Negative control (planning-class red-capable A/B reproduction)

- **[RED]** Under a `PR_SET_DUMPABLE=0` hidden supervisor ancestor on Linux `/proc` `hidepid=invisible`: `tests.test_spawn_worker.TestUnknownIsNeverAbsent.test_a_response_that_does_not_parse_whole_registers_what_it_names` deterministically fails (`exit_code: 1`, `AssertionError: "parent profile 'rw'" not found` — child capped at `ro` via `spawn_identity.py:474 -> :196`).
- **[CONTROL A]** Exact same test on the exact same commit without a hidden supervisor `> 1`: passes (`OK`, `exit_code: 0`).
- Rivals H2 (`own_proc`), H3 (`python3 -I` CLI / `setsid` / `Registry`), and H4 (`_uids`) falsified via 6 literal self-contained probes; path-free durable `agent-brief` archived with sound transitive shared-hidden-parent W4-04 invariant and 4 fail-closed negative controls.

## Integrity inventory (sha256)

| Artifact | sha256 | producer |
|---|---|---|
| `negctrl.txt` | `7c5b1bbb96cd2f6be8e2345b254d1b1eee8dcfdc1df2fa9142f6220d5aa95d93` | deterministic A/B hidepid reproduction (2026-11-25) |

## Runner credit

Runner: Ravindra Kumar (@ravidsrk) · 3-round independent build-blind review (`R1 NO-GO -> R2 NO-GO -> R3 GO`).
