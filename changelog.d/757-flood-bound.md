- **The ledger-flood test no longer fails loaded CI runners** (#757). Its fixed 50-line cap is
  measured against 1 s record windows, so a loaded runner whose flood spanned more windows wrote
  53 and 56 correctly rate-limited lines and failed main's `validate` three runs running. The test
  now runs the broker with a 3 s window, with its assertions unchanged: it still fails at about 200
  lines when every fault is written. The worker and terminal wrappers also document every flag.
