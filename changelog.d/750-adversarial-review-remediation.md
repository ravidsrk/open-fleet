- **Remediation of all 42 adversarial-review findings across verifier, runtime scripts, providers,
  and CI** (#750). `scripts/bundle.py` refuses symlinked files and directories across mission,
  runtime, protocol, plugin, and support-document sources (`C2`). `runtime/scripts/deny-hook.sh`
  validates Python interpreter ownership and non-writability by group/others at both check and
  execution time and leaves `busybox --install [-s] [DIR]` unpeeled (`C18`, `D2`).
  `runtime/scripts/verify.py` and `runtime/scripts/merge_queue.py` pin resolved executable paths and
  `SHA-256` digests across negative-control and merge-gate phases, isolate merge-gate clones with
  `--no-local` and detached Git config/hooks, default `execute_nc=True` on reviewed mutation units,
  replay all eight accepted mutation tools, and verify quiet `oss-contribute` PRs (`C10`, `C11`,
  `C15`, `C19`, `C21`). `runtime/scripts/decisions.py` and `runtime/scripts/gate-batch.py` walk past
  submodules to the outermost superproject (`C20`). `runtime/providers/local_state.py`,
  `runtime/providers/posix.py`, and the 12 external orchestrator adapters enforce Run boundaries,
  coordinator-takeover fencing, local task claiming (`ready -> dispatched`) and settlement on
  `worker_done`/`worker_died`, atomic payload-bound request idempotency, ambient-Git-immune state DB
  resolution, forward terminal/worker cursor pagination with `source`/`truncated` metadata, `0600`
  inbox/message permissions with fence cleanup, and preserved refs on Multiclaude release (`C1`,
  `C24`, `C28`–`C35`, `C37`, `C38`, `C40`). `scripts/live_broker.py` and
  `runtime/scripts/events.py` recover existing spend ledgers on restart without leaking request
  fragments and preserve cross-Run conflict state and blank-line tamper evidence (`C39`, `C41`,
  `C42`, `C43`). Mission contracts, docs, fixture lockfiles, and regression tests are aligned across
  `C4`–`C9`, `C12`–`C14`, `C16`, `C17`, `C25`, `C26`, `D1`, `D3`, and `T1`.
