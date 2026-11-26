# Diagnosis Evidence — `root-cause-2026-11-25-hidepid`

- **Unit ID:** `root-cause-2026-11-25-hidepid`
- **Mission:** `root-cause` (planning class; zero production or test code modified)
- **Fixed point inspected:** `cfa3bd63f78df5f0e5e7ee66817ba466d860340b` (`runtime/scripts/spawn_identity.py`, `runtime/scripts/spawn_worker.sh`, and `tests/test_spawn_worker.py` unchanged since `4b2e99e523fe235fd30aab2e68612d616787c3dc`)
- **Terminal outcome:** `DIAGNOSED-WITH-HANDOFF` (see path-free durable brief in `handoff-brief.md`)

## 1. Prior-Art Check (`playbooks/diagnose.md`)

Executed verbatim in `falsification-probes.txt`:
- `git grep -n spawn_identity docs/runs/` → `(0 matches in docs/runs/)`.
- `command -v orca orca-ide` → `(orca/orca-ide not installed on PATH)`.

No prior catalog run reports or diagnoses touch `runtime/scripts/spawn_identity.py`.

## 2. Deterministic Red-Capable Reproduction & A/B Control (`repro-red.txt`)

- **Host environment (`falsification-probes.txt`):** Linux with `proc /proc proc rw,relatime,gid=987,hidepid=invisible 0 0`, UID `1002`, `/proc/1` absent (`False`).
- **A/B single-variable proof (`repro-red.txt`):**
  - **[RED]** Under a hidden supervisor ancestor (`PR_SET_DUMPABLE=0` parent hidden by `hidepid=invisible`, mirroring a root-owned container supervisor): `tests.test_spawn_worker.TestUnknownIsNeverAbsent.test_a_response_that_does_not_parse_whole_registers_what_it_names` deterministically fails (`exit_code: 1`, `FAILED (failures=1)`) at `tests/test_spawn_worker.py:2482` → `:2231` with:
    `AssertionError: "parent profile 'rw'" not found in "SPAWN=NOTE task=task_child this session's spawn identity cannot be read (...): the child is capped at ro rather than left uncapped (W4-04)..."`
  - **[CONTROL A]** Running the exact same test on the exact same commit when the parent chain reaches PID 1 directly (no hidden supervisor ancestor `> 1`): `Ran 1 test ... OK` (`exit_code: 0`).

## 3. Ranked Hypotheses & Single-Variable Falsification (`falsification-probes.txt`)

| Rank | Hypothesis | Literal Probe Executed (`falsification-probes.txt`) | Verbatim Result | Verdict |
|---|---|---|---|---|
| 1 | **H1** — `/proc` `hidepid=invisible` hides a supervisor ancestor (`ppid > 1`, `stat(ppid) is None`), so once `reg.live_roots()` is non-empty, `whoami()` flips `allow_hidden=not live` to `False` and raises `Unknown` | Spawned `PR_SET_DUMPABLE=0` supervisor (PID `546338`) → child PID `546371` (`hidden_parent_pid=546338`): ran `chain(546371, allow_hidden=True/False)` and `whoami(reg, 546371)` with empty vs non-empty `.roots` (`registered_live_root=546371.359425745`) | `whoami(empty_reg, 546371) -> OK lines=3 last=SELF 546371.359425745`; `chain(546371, allow_hidden=False) RAISED Unknown: ancestor 546338 of 546371 cannot be read`; `whoami(nonempty_live_root_reg, 546371) RAISED Unknown: ancestor 546338 of 546371 cannot be read` | **SURVIVES (DEMONSTRATED)** |
| 2 | **H2** — `own_proc()` PID-namespace mismatch | Executed `spawn_identity.own_proc()` | `readlink(/proc/self)=546302 == pid=546302 -> own_proc: OK` (`exit_code: 0`) | **FALSIFIED** |
| 3 | **H3** — `python3 -I` CLI, `setsid`, or `Registry` permissions fail | Executed `python3 -I runtime/scripts/spawn_identity.py --help`, `command -v setsid`, and `Registry.write/entries/live_roots` | `spawn_identity --help: OK`, `/usr/bin/setsid`, `live_roots={'546218.359425724': 'rw'}` (`exit_code: 0`) | **FALSIFIED** |
| 4 | **H4** — `_uids(pid)` fails to parse `/proc/<pid>/status` | Executed `spawn_identity._uids(os.getpid())` | `_uids(546337)=(1002, 1002, 1002, 1002)` (`exit_code: 0`; and `whoami()` never calls `_uids()`) | **FALSIFIED** |

## 4. Verbatim Source Seam Proof (`cfa3bd63f78df5f0e5e7ee66817ba466d860340b`)

- `runtime/scripts/spawn_identity.py:473-474` (`whoami`):
  ```python
      live = reg.live_roots()
      mine = chain(pid, allow_hidden=not live)
  ```
- `runtime/scripts/spawn_identity.py:194-196` (`chain`):
  ```python
              if allow_hidden:
                  break
              raise Unknown(f"ancestor {pid} of {child} cannot be read")
  ```
- `runtime/scripts/spawn_identity.py:483-489` (W4-04 `HOME`-switch defense — must be evaluated alongside `reg` before authorizing any hidden-boundary stop):
  ```python
      pw_dir = _uid_home()
      if pw_dir:
          uid_reg = Registry(str(Path(pw_dir) / ".open-fleet" / "spawn-profiles"))
          if os.path.realpath(str(uid_reg.root)) != os.path.realpath(str(reg.root)) and uid_reg.root.is_dir():
              uid_live = _read_only_live_roots(uid_reg)
              uid_hosts = _read_only_live(uid_reg, ".hosts")
              if ancestors & (set(uid_live) | set(uid_hosts)):
  ```
- `runtime/scripts/spawn_identity.py:601-612` (`own_proc` — unchanged PID-namespace check).
- `runtime/scripts/spawn_identity.py:165-170` (`alive` — returns `False` when `stat` returns `None`, and `None` only when `stat` raises `Unknown`).
- `runtime/scripts/spawn_worker.sh:654,696` — runs `spawn_identity.py whoami ... 2>/dev/null` and emits `SPAWN=NOTE ... capped at ro (W4-04)` on non-zero exit.

## 5. Security Boundary Analysis (Transitive Evasion Prevention)

Simply stopping `chain(pid)` at an invisible ancestor whenever `all(alive(k) is True for k in live)` is **unsound** under `hidepid=invisible`: a visible `ro` worker root `R` can spawn a non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) or setuid intermediate `S` (`stat(S) -> None`) which spawns child `C`; stopping `C`'s walk at `S` misses `R` sitting above `S` and drops the `ro` cap.

The sound condition specified in `handoff-brief.md` requires every live root AND live host across both `reg` and `uid_reg` to be visible (`alive == True`) AND have its own upward walk terminate at the **exact same live hidden parent PID `P`** (re-verified via `stat(top_visible)[0] == P`). Because the process tree is acyclic and `P` is an active parent of each root's/host's topmost visible ancestor, no live root or host can sit above `P`.
