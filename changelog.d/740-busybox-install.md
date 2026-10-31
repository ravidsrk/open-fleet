- **The deny hook judges `busybox --install sh -c '…'` as the shell it names** (#740). The
  2026-10-29 audit noted that `--install` shifted the applet, so the body was never read and the
  line was allowed. `_peel_busybox` now skips a leading `--install` (and its `-s`) before peeling,
  failing closed. `busybox --install -s DIR`, with no applet after it, keeps its decision.
