- **`wtree.sh` fingerprints the repository it is given, and its custody copies can no longer hang
  or be redirected** ([2026-10-27 security audit](../docs/runs/2026-10-27-security-audit.md),
  W4-02 follow-up, Codex round 5). `$(...)` stripped the trailing newline of a repository path
  that ends in one, so `wtree.sh` fingerprinted the repository at the stripped path, a different
  one, and printed its tree. Every path git hands the script (toplevel, git dir, common dir,
  index) and every carried `core.*` value is now read byte-exact; a linked worktree whose path
  ends in a newline fingerprints itself, and a common git dir an alternates file cannot name is
  exit 1. The custody copies (`info/exclude`, `info/attributes`, `shallow`,
  `info/sparse-checkout`, `sharedindex.*`, the index seed and the `core.attributesFile` content)
  were type-checked by path and then opened by `cp` by path again, so a worker that swapped in a
  FIFO in between hung the coordinator and a symlink was followed. Each is now opened once by
  `python3 -I` without blocking or following a final symlink, checked with `fstat` on that
  descriptor, size-capped (16 MiB, 1 GiB for the index and shared index, 1 MiB for
  `core.attributesFile`) and copied from it; anything else is exit 1. `wtree.sh` now needs a
  `python3` on PATH.
