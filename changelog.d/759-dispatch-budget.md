- **Every mission now activates with the per-dispatch timebox, and headless claude workers can
  carry a spend cap** (#759). The timebox + partial-report STOP and the stuck-but-alive ladder were
  only in `worker-supervision.md`, which 1 of 22 missions loaded; the rule now sits in the worker
  contract (`dispatch-lifecycle.md`) and in `liveness-resume.md`, so no mission waits on a wedged
  worker without an end. `OPEN_FLEET_MAX_BUDGET_USD` becomes `--max-budget-usd` on every claude
  launch `base.py` builds (all non-Orca runtimes), a malformed value refuses on every runtime, and
  `OPEN_FLEET_REQUIRE_BUDGET=1` refuses an uncapped claude spawn. Orca's own launch lanes cannot
  carry the flag and say so. prove-it and root-cause budgets rise by the added rule.
