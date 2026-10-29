- **`search_sessions.py` no longer parses `--current-evidence` in its own process, and the live
  broker's bodies no longer wait on one another for their parses**
  ([2026-10-27 security audit](../docs/runs/2026-10-27-security-audit.md), W5-21, W5-16; Codex
  round 13 on 594f7265). The episodic hint read the frozen task's evidence file under the byte cap
  and then `json.loads`-ed it in the parent before its shape was checked, so a ~60 MiB array of
  empty objects built some 20 million dicts outside the scan's memory limit. The file is now read,
  parsed and shape-checked in a contained child of its own (`SCAN_MEMORY_BYTES`,
  `SOURCE_SECONDS`), as the manifests are, and only the checked observations cross back: at most
  `MAX_OBSERVATIONS` (4,096), each path at most 1,024 characters, within `RESULT_BYTES`. Anything
  else -- unreadable, not UTF-8 JSON, nested past the parser's depth, the wrong shape, past a bound,
  or a parse past a limit -- refuses the hint whole (exit 2), and the library entry holds evidence
  handed to it to the same bounds. No other file `search_sessions.py` reads is parsed in the parent.
  In `live_broker.py`, a body read in full whose JSON values need more budget than it took before it
  was read (13 times its bytes) waited for the rest holding that share, and bodies completed
  together (32 of ~1 MB, ~416 MB of first shares) waited on one another until every one was answered
  503. Now at most one request waits for budget while holding any: of the bodies read in full, one
  may wait for its larger charge, and while it waits every other take leaves what it needs free;
  any other whose charge does not fit at once is answered 503 at once and gives back all of its
  share but its bytes'. A parsed body also gives back its parse's share before it is relayed,
  keeping only its bytes', and on every way out of a request -- an exception included -- the
  bytes' share goes back only once the body's buffer has been freed.
