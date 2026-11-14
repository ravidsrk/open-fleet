- **Every mission now activates with the per-dispatch timebox, and headless claude workers can
  carry a spend cap** (#759). The timebox + partial-report STOP and the stuck-but-alive ladder were
  only in `worker-supervision.md`, which 1 of 22 missions loaded; the rule now sits in the worker
  contract (`dispatch-lifecycle.md`) and in `liveness-resume.md`, so no mission waits on a wedged
  worker without an end. `OPEN_FLEET_MAX_BUDGET_USD` becomes `--max-budget-usd` in the `claude -p`
  argv `base.py` builds, which the posix and worktrunk runtimes execute; every other runtime (and
  an override command) prints that the cap is not carried. A malformed value refuses on every
  runtime, and `OPEN_FLEET_REQUIRE_BUDGET=1` refuses a claude spawn the cap does not reach.
  prove-it and root-cause budgets rise by the added rule.
