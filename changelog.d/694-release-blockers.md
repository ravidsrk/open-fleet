- **A run report can bind only to the directory named for it** (#694 and #695 reviews).
  `run_report.py`'s `run_directory` took the alphabetically first same-day directory that named
  the mission. So `2026-10-25-trajectories-602-live.md` was checked against `…-602-adapters/` and
  failed to bind, although the run index listed it as binding. A report of any name could also
  borrow a mission's only same-day directory, with its manifest and inventory. The directory is now
  the report's exact stem, or the stem less a tier suffix (`self-run` also spelled `selfrun`), or
  the closed legacy entry for `2026-09-14-clean-sweep-self-run`; otherwise the check fails closed.
  Every report the index lists as binding still binds. The roadmap, the concepts page,
  `ARCHITECTURE.md`, `wip_curve.py` and the A2A example no longer describe #604 as unmeasured or
  pin the 0.8.0 version.
