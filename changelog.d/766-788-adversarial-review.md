- **Security and correctness hardening across verification, hooks, runtimes, broker, CI, and
  missions** (#766, #767, #768, #769, #770, #771, #772, #773, #774, #775, #776, #777, #778, #779,
  #780, #781, #782, #783, #784, #785, #786, #787, #788). Scrubs git execution environment
  variables (`GIT_CONFIG_PARAMETERS`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_EXEC_PATH`,
  `core.hooksPath`, `core.fsmonitor`) across `gitexec.py`, shell gates, and harnesses (#766);
  closes the `[[` brace-splitting bypass and six command/tool gaps in `deny-hook.sh` (#767);
  binds `verify.py` manifest command hashes, negative-control execution, and signature checks
  fail-closed (#768); pins CI `ruff.toml`, `COVERAGE_RCFILE`, `PYTHONSAFEPATH=1`, and extends
  the W3-01 `sys.path[0]` guard across all entry points including `bench/vf-bench/` (#769, #770);
  migrates CI runners off CodeBuild to `ubuntu-latest` (#771); enforces `--pin-ref` and
  `--base` decision ledger integrity, `floor_guard` full-diff scanning, `certification.py`
  witness binding, and `verdict_check.py` review binding (#772, #779, #782); hardens
  `merge_queue.py`, `local_state.py`, `sandbox_doctor.py`, provider isolation, CLI argument
  delimiters, `live_broker.py` spend/body limits, and `eval.py`/`hint_replay.py` parsing (#773,
  #774, #775, #776, #777, #778, #785, #786); enforces step-0 `preflight.py --mission` across all
  22 missions, fixes `diff_scope.py` rename/untracked coverage, closes prompt-guard/playbook
  and path-containment gaps, fixes `target-app` lock/cookie/rate-limit issues, and hardens URL
  encoding and pagination fail-closed behavior (#780, #781, #783, #784, #787, #788).
