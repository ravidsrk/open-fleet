- **The ledger-flood test no longer fails loaded CI runners** (#757). It capped a rate-limited
  ledger at a fixed 50 lines, contradicting its own per-second bound, so main's `validate` failed
  three runs running on 53 and 56 lines. The test keeps the per-second bound and still fails on
  one line per fault. The bundle's executable-bit check now follows the source's mode, so it
  passes under a restrictive umask, and the worker and terminal wrappers document every flag.
