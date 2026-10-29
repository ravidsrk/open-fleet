- **The spawn path's identity inputs are bounded: the parent-profile cap reaches Orca workers,
  CLI commands and installer operands are validated, and printed receipt fields are inert**
  ([2026-10-27 security audit](../docs/runs/2026-10-27-security-audit.md): W4-04, W4-10, W4-11,
  W4-12, W4-13, W4-15/W2-03, W2-05/W5-22, W5-19, W5-20). The CLI resolver that `spawn_worker.sh`
  runs first now runs under `python3 -I`, so a caller's PYTHONPATH cannot shadow it.
  `spawn_worker.sh` records every launch's profile under the pane handle the runtime returns
  (`~/.open-fleet/spawn-profiles/`), so a spawn from that pane is capped at it on Orca as well as
  posix. Each launch reserves its profile there before any launch call (an unwritable registry or
  an unset `HOME` refuses the spawn), and registration records the worker's pane root process by
  pid and start time (`spawn_identity.py`), so a spawn inside the worker's pane process tree is
  capped by its ancestry even when its harness drops `ORCA_*`; a session nothing identifies waits on open reservations
  and is capped at any still open, and inside a provider's process tree at the live workers,
  unless it is an anchored coordinator. Every response that names a pane handle (`worker-start`,
  `terminal create`, the `request-show` triage) is read by one extraction before anything judges
  it, wherever the handle sits (an error envelope beside a ready result included, and a response
  that does not parse whole or reads two ways: every occurrence of a duplicated key), and each
  handle is registered whatever the exit code, error code or state; a refused or failed verdict
  prints the pane it names. Registering a pane other than the worker's own (a coordinator-role,
  unknown-role or role-less one) never releases the reservation: only the worker's agent-role
  pane, named and completely recorded, does. Every other reader of a runtime response refuses one that reads two
  ways (a duplicate key, `NaN`, a number that overflows) as unparseable. A session whose
  identity cannot be read is capped at `ro` even when the failing read is one made while it
  waits on a reservation. A launch that may have left a
  worker live without a complete record keeps its reservation; with no handle named, it is
  released only on a response that is exactly one refusal proven to precede any launch effect (a
  strict schema at every level, an allowlist of pre-launch codes, on both launch paths), never for
  a second or nested error, an extra field, `runtime_error`, an unknown or untyped code, or a
  policy refusal that can follow a pane's creation. A process environment the scan
  cannot read (`EACCES`, `EIO`; re-read for a moment first, since a process caught exiting
  answers `EACCES` briefly) leaves the scan incomplete, so finding nothing is unknown, never "no
  process", and the same holds without `/proc` (`ps -E`); a pane that is found is recorded. Any other identity read that fails, a `/proc` of another pid
  namespace included, is unknown rather than absent: the reservation stays, or the caller is
  capped at `ro`. Not covered: a
  worker process outside its pane's process tree whose environment drops the handle (daemonized
  out, run from a process outside the pane, or in another pid namespace), a worker whose `HOME`
  differs, and a pane process that carries no handle; whether a harness does these as ordinary
  behaviour is unwitnessed. A session carrying fleet worker identity with no profile is
  capped at `ro` and a `--parent-profile` flag cannot raise that; a capped session cannot use a
  command override. These are the worker's own environment and files: a guard on the spawn path,
  not a sandbox.
  The title label is bounded and never option-shaped. `OPEN_FLEET_CLI_COMMAND` /
  `ORCA_CLI_COMMAND` must name one executable with no invisible character, and one resolution in
  `orca_cli.py` now serves the Orca provider, `auto`, `preflight.py`, `install.sh` and
  `upstream_probe.py`. `sandbox_doctor.py` reads the recipe from recipe fields only, refuses a
  malformed recipe field, a repeated JSON key and an envelope that contradicts the report at any
  wrapping level or depth (its `metadata` included), reads a report out of every wrapper (up to
  16; more, nesting too deep to parse, and output that opens as JSON by the grammar's first
  token but does not parse are refused, never read as a report or as text), refuses every output shape but one report object (an array, a scalar, a
  list as `result`, a nested or misspelt `backend`), and reads placement claims in every
  spelling. `worker_ops.py`, `terminal_ops.py`, `send_msg.py`, `check_reply.py`,
  `orca_cli.run_json`, `pm.py` and `spawn_worker.sh` print every receipt field, and every error
  and exception message (the provider-dispatch path included), escaped and on one line; no body line, tail item or list row stands at column 0 in the shape of a line those
  printers write (`KEY=`, `---`, `===`, a `(…)` marker, a printer's own `SUBJ:`/`ID:` headers),
  the first body line included;
  a failed sandbox doctor's output and `sandbox_doctor.py`'s reason print escaped; and a lone
  surrogate no longer crashes the printer.
  `send_msg.py` and `check_reply.py` say their sender check catches accidental mismatches only.
  `first_run.py` hands its on-host sandbox an allowlisted environment (locale names by name), so
  no operator credential reaches the worker. `scripts/install.sh` refuses an empty or
  option-shaped `--skills-dir`, ends `mkdir`/`ln` options with `--`, validates mission names from
  the directory entry before any mutation, and names an unset `HOME`.
