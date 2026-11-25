- **Post-#788 adversarial hardening and first-principles product shell (`open-fleet` CLI, MCP server,
  and Mission Control UI)**. Closes 5 P0 and 29 P1 security/reliability findings across `guard_text.py`
  (`--fetch` path-qualified binary execution and `wget`/`curl` read-only bypasses), `deny-hook.sh`
  (Rule 5 egress receipt spoofing, `--verify-settings` boundary forgery and ambient env contamination,
  GNU `rm` long-option prefix bypass, and `HOOK_READONLY=1` `/dev/null` handling), `verify.py`
  (`--execute-nc` phase ref isolation, malformed record guards, wrapper parity, `_extract_diff`
  newline splitting, and early sound-lane transcripts), `floor_guard.py` (`ls-tree` pin reads and
  structural TOML/INI guard-surface diffing), `decisions.py`/`gitexec.py`/`preflight.py`/
  `dispatch-sign.py`/`spawn_worker.sh`/`spawn_identity.py` (custody env, `worktrunk` W4-04 root
  tracking, `HOME` fallback, W3-01 package loading, CR/Unicode line-break rejection, and seed custody),
  `runtime/providers/` (`get_provider("auto")`, `_external.py` pre-launch contact rollback across 9
  adapters, `sandbox_doctor.py` shadowing/envelope checks, `worktrunk` guarded `HERMES_HOME`,
  `emdash`/`t3code`/`posix`/`multiclaude` worker isolation, `posix` `self.env` propagation and
  `_terminate_backend` resilience, `orca_cli.py`, `events.py`, `watchdog.py`, `send_msg.py`/
  `check_reply.py`/`hitl_ask.py` `OPEN_FLEET_TERMINAL_HANDLE`, `search_sessions.py`, `merge_queue.py`,
  and `proof_status.py`), plus `live_broker.py` UTF-8/BOM validation, `live_container.py` signal
  teardown fail-closed exit, `bundle.py` pre-install abort, `run_index.py` binding cross-checks,
  `bench/vf-bench/replay.py` static `allow_static_nc`, CI workflow pinning, and doc drift
  reconciliation. Adds root [`pyproject.toml`](../pyproject.toml) and the zero-dependency `open_fleet`
  package delivering the unified `open-fleet` CLI (`doctor`, `setup`, `missions`, `route`, `status`,
  `certify`, `demo`, `preflight`, `verify`, `floor`, `mcp`, `ui`), a JSON-RPC 2.0 stdio MCP server
  (`open-fleet mcp`: 12 tools, 8 resources, and mission prompts), and the interactive Mission Control
  web cockpit ([`docs/cli-and-mcp.md`](../docs/cli-and-mcp.md),
  [`docs/product-blueprint.md`](../docs/product-blueprint.md)).
