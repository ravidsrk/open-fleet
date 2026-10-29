- **`spawn_identity.py` decides whose a process is from its credentials, not its `/proc` owner**
  ([2026-10-27 security audit](../docs/runs/2026-10-27-security-audit.md), W4-04, Codex round 10).
  The registration scan skipped every process whose `/proc/PID` was not owned by this uid before
  it tried to read the environment. That owner is the effective uid alone, and root for every file
  of a non-dumpable process, so a same-uid pane running a setuid program read as another user's:
  skipped, the scan "complete", `record-root` answered "no process" (3) and `spawn_worker.sh`
  released the reservation, leaving the pane's scrubbed descendants uncapped. A process now counts
  as this uid's when any of the real, effective, saved and filesystem uids on the `Uid:` line of
  `/proc/PID/status` is this uid; one whose `status` cannot be read or holds no single
  well-formed `Uid:` line leaves the scan incomplete (1, the reservation kept); one none of whose
  uids is this uid is still skipped. New tests isolate the process listing to the process under
  test, so an unrelated unreadable process on the host can no longer supply the expected answer.
