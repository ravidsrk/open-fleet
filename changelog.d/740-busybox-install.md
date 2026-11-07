- **The deny hook leaves `busybox --install [-s] [DIR]` unpeeled instead of treating `DIR` as an
  applet** (#740, #750). In BusyBox, `--install [-s] [DIR]` takes an optional target directory
  operand rather than an applet name; `_peel_busybox` peels only leading applet invocations (`busybox
  sh -c '…'`), avoiding false denials when `DIR` matches an applet name.
