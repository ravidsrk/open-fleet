//! Native Rust port of `runtime/scripts/deny-hook.sh` — PreToolUse shell & file-tool guardrail,
//! self-guard, read-only write floor, egress receipt gate, SQLite WAL file-touch recorder,
//! and multi-harness `--settings` / `--verify-settings` engine.

pub mod guard_rules;
pub mod path_guard;
pub mod policy;
pub mod settings;
pub mod shell_parse;
pub mod shlex_util;
pub mod touch_db;
pub mod types;

use std::ffi::OsString;
use std::io::{self, Read};
use types::{emit_decision, DecisionKind, HookConfig};

/// Top-level CLI entry point for `open-fleet hook --mode deny` and `open-fleet deny-hook`.
pub fn run_raw(args: &[OsString]) -> i32 {
    if let Some(first) = args.first() {
        let s = first.to_string_lossy();
        match s.as_ref() {
            "-h" | "--help" => {
                print!("{}", settings::usage_text());
                return 0;
            }
            "--settings" => return settings::run_settings(&args[1..]),
            "--verify-settings" => return settings::run_verify_settings(&args[1..]),
            other => {
                eprintln!("deny-hook.sh: unexpected argument: {other}");
                eprint!("{}", settings::usage_text());
                return 2;
            }
        }
    }

    let mut cfg = HookConfig::from_env();
    let mut payload = String::new();
    let _ = io::stdin().read_to_string(&mut payload);

    let parsed = match shell_parse::parse_payload(&payload, &cfg) {
        Ok(p) => p,
        Err(_) => {
            // Unparseable or empty payload ALWAYS forces strict exit 2.
            return emit_decision(
                DecisionKind::Deny,
                "deny-hook: the tool payload is empty or could not be parsed. Fail-closed: an unreadable payload is refused, never allowed.",
                true,
                cfg.headless_strict,
                cfg.goose_mode,
            );
        }
    };

    if parsed.strict_payload {
        cfg.hook_strict = true;
    }

    let report = guard_rules::evaluate(&parsed, &cfg);
    policy::evaluate(&parsed, &report, &cfg)
}
