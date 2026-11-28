//! Shared types, environment configuration, and JSON decision formatting for `of-hook`.

use of_install::find_catalog_root;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Sentinel recorded when a nested body cannot be parsed/split cleanly.
pub const UNSPLIT_SENTINEL: &str = "\x00UNSPLIT";

/// Private-use sentinel representing a quoted newline inside token values.
pub const QNL: char = '\u{E000}';

pub fn truthy_opt(v: Option<&str>) -> bool {
    matches!(v, Some(s) if !s.is_empty() && s != "0")
}

pub fn truthy_env(name: &str) -> bool {
    env::var(name)
        .ok()
        .as_deref()
        .is_some_and(|s| !s.is_empty() && s != "0")
}

pub fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoWriteKind {
    Write,
    Blind,
}

#[derive(Debug, Clone)]
pub struct HookConfig {
    pub unit_worktree: Option<String>,
    pub dh_self: Option<PathBuf>,
    pub current_exe: Option<PathBuf>,
    pub hook_strict: bool,
    pub hook_readonly: bool,
    pub headless_strict: bool,
    pub goose_mode: bool,
    pub cwd: PathBuf,
    pub groot: PathBuf,
    pub gself: BTreeSet<PathBuf>,
    pub egress_sibling: Option<PathBuf>,
    pub state_db: Option<String>,
    pub worker_id: String,
    pub run_id: String,
    pub home: String,
    pub jcode_tool_name: Option<String>,
}

impl HookConfig {
    pub fn from_env() -> Self {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let cwd_real = fs::canonicalize(&cwd).unwrap_or_else(|_| cwd.clone());

        let unit_worktree = non_empty_env("OPEN_FLEET_UNIT_WORKTREE")
            .or_else(|| non_empty_env("ORCA_UNIT_WORKTREE"));

        let current_exe = env::current_exe()
            .ok()
            .map(|p| fs::canonicalize(&p).unwrap_or(p));

        let dh_self = resolve_canonical_hook_script(&cwd_real, current_exe.as_deref());

        let groot = match unit_worktree.as_deref() {
            Some(wt) => fs::canonicalize(wt).unwrap_or_else(|_| PathBuf::from(wt)),
            None => cwd_real.clone(),
        };

        let mut gself = BTreeSet::new();
        for env_key in ["DH_SELF", "OPEN_FLEET_DENY_HOOK", "ORCA_DENY_HOOK_PATH"] {
            if let Some(p) = non_empty_env(env_key) {
                let pb = PathBuf::from(&p);
                gself.insert(fs::canonicalize(&pb).unwrap_or(pb));
            }
        }
        if let Some(ref s) = dh_self {
            gself.insert(fs::canonicalize(s).unwrap_or_else(|_| s.clone()));
        }
        if let Some(ref exe) = current_exe {
            gself.insert(exe.clone());
        }

        let egress_sibling =
            resolve_egress_sibling(dh_self.as_deref(), &cwd_real, current_exe.as_deref());

        let jcode_tool_name = non_empty_env("JCODE_HOOK_TOOL_NAME");
        let hook_strict = truthy_env("ORCA_HOOK_STRICT_EXIT")
            || truthy_env("OPEN_FLEET_HOOK_STRICT_EXIT")
            || truthy_env("OPEN_FLEET_HOOK_EXIT2")
            || jcode_tool_name.is_some();

        let hook_readonly = truthy_env("OPEN_FLEET_HOOK_READONLY")
            || truthy_env("ORCA_HOOK_READONLY")
            || env::var("OPEN_FLEET_SANDBOX_PROFILE").ok().as_deref() == Some("ro")
            || env::var("ORCA_SANDBOX_PROFILE").ok().as_deref() == Some("ro");

        let headless_strict = truthy_env("CODEX_CI")
            || truthy_env("CODEX_SANDBOX")
            || truthy_env("OPEN_FLEET_HEADLESS_STRICT");

        let goose_mode = truthy_env("GOOSE_MODE");

        let state_db =
            non_empty_env("OPEN_FLEET_STATE_DB").or_else(|| non_empty_env("ORCA_FLEET_STATE_DB"));

        let worker_id = non_empty_env("OPEN_FLEET_WORKER_ID")
            .or_else(|| non_empty_env("ORCA_WORKER_ID"))
            .or_else(|| non_empty_env("OPEN_FLEET_DISPATCH_ID"))
            .or_else(|| non_empty_env("ORCA_DISPATCH_ID"))
            .or_else(|| non_empty_env("OPEN_FLEET_TERMINAL_HANDLE"))
            .or_else(|| non_empty_env("ORCA_TERMINAL_HANDLE"))
            .unwrap_or_else(|| {
                if let Some(ref wt) = unit_worktree {
                    let r = fs::canonicalize(wt).unwrap_or_else(|_| PathBuf::from(wt));
                    format!("wt:{}", r.display())
                } else {
                    "worker".to_string()
                }
            });

        let run_id = non_empty_env("OPEN_FLEET_RUN_ID")
            .or_else(|| non_empty_env("ORCA_RUN_ID"))
            .unwrap_or_else(|| "default".to_string());

        let home = env::var("HOME").unwrap_or_default();

        Self {
            unit_worktree,
            dh_self,
            current_exe,
            hook_strict,
            hook_readonly,
            headless_strict,
            goose_mode,
            cwd: cwd_real,
            groot,
            gself,
            egress_sibling,
            state_db,
            worker_id,
            run_id,
            home,
            jcode_tool_name,
        }
    }

    pub fn resolved_bound(&self) -> Result<Option<PathBuf>, String> {
        let Some(ref wt) = self.unit_worktree else {
            return Ok(None);
        };
        let p = Path::new(wt);
        if !p.is_dir() {
            return Err(
                "deny-hook: ORCA_UNIT_WORKTREE is set but does not resolve to a directory. Fail-closed."
                    .to_string(),
            );
        }
        match fs::canonicalize(p) {
            Ok(real) if real.is_dir() => Ok(Some(real)),
            _ => Err(
                "deny-hook: ORCA_UNIT_WORKTREE is set but does not resolve to a directory. Fail-closed."
                    .to_string(),
            ),
        }
    }
}

pub fn resolve_canonical_hook_script(cwd: &Path, current_exe: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = non_empty_env("DH_SELF") {
        let pb = PathBuf::from(p);
        return Some(fs::canonicalize(&pb).unwrap_or(pb));
    }
    for key in ["OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT"] {
        if let Some(root) = non_empty_env(key) {
            let cand = PathBuf::from(root).join("runtime/scripts/deny-hook.sh");
            if cand.is_file() {
                return Some(fs::canonicalize(&cand).unwrap_or(cand));
            }
        }
    }
    if let Some(root) = find_catalog_root(cwd) {
        let cand = root.join("runtime/scripts/deny-hook.sh");
        if cand.is_file() {
            return Some(fs::canonicalize(&cand).unwrap_or(cand));
        }
    }
    if let Some(exe) = current_exe {
        let mut cur = exe.parent();
        while let Some(dir) = cur {
            let cand = dir.join("runtime/scripts/deny-hook.sh");
            if cand.is_file() {
                return Some(fs::canonicalize(&cand).unwrap_or(cand));
            }
            cur = dir.parent();
        }
    }
    None
}

pub fn resolve_egress_sibling(
    dh_self: Option<&Path>,
    cwd: &Path,
    current_exe: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(self_p) = dh_self {
        if let Some(dir) = self_p.parent() {
            let sib = dir.join("egress.py");
            if sib.is_file() {
                return Some(fs::canonicalize(&sib).unwrap_or(sib));
            }
        }
    }
    for key in ["OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT"] {
        if let Some(root) = non_empty_env(key) {
            let cand = PathBuf::from(root).join("runtime/scripts/egress.py");
            if cand.is_file() {
                return Some(fs::canonicalize(&cand).unwrap_or(cand));
            }
        }
    }
    if let Some(root) = find_catalog_root(cwd) {
        let cand = root.join("runtime/scripts/egress.py");
        if cand.is_file() {
            return Some(fs::canonicalize(&cand).unwrap_or(cand));
        }
    }
    if let Some(exe) = current_exe {
        let mut cur = exe.parent();
        while let Some(dir) = cur {
            let cand = dir.join("runtime/scripts/egress.py");
            if cand.is_file() {
                return Some(fs::canonicalize(&cand).unwrap_or(cand));
            }
            cur = dir.parent();
        }
    }
    None
}

/// One peeled command view produced by `shell_parse::_views`.
#[derive(Debug, Clone)]
pub struct CommandView {
    pub assigns: Vec<String>,
    pub words: Vec<String>,
    pub writes: Vec<String>,
    pub seg_text: String,
    pub is_top: bool,
}

/// Complete structured output of the Stage-1 payload reader & shell analyzer.
#[derive(Debug, Clone)]
pub struct ParsedPayload {
    pub raw_tool: String,
    pub norm_tool: String,
    pub raw_command: String,
    pub judged: String,
    pub parts: Vec<String>,
    pub subs: Vec<String>,
    pub target_paths: Vec<String>,
    pub file: String,
    pub extra_files: Vec<String>,
    pub heredoc_targets: Vec<String>,
    pub unparseable_patch: bool,
    pub strict_payload: bool,
    pub c_records: Vec<String>,
    pub a_records: Vec<String>,
    pub guard_segs: Vec<(Vec<String>, Vec<String>)>,
    pub all_views: Vec<CommandView>,
    pub body_texts: Vec<String>,
    pub w_records: Vec<String>,
    pub fed_sub: bool,
    pub fed_interp: Vec<String>,
    pub fed_blind: bool,
    pub brace_refusal: Option<String>,
    pub unreceipted_egress: bool,
    pub rline: String,
    pub ro_write_kind: Option<RoWriteKind>,
    pub payload_json: Value,
}

/// Verdicts produced by `guard_rules` (`D`, `G`, `Y`, `N` records in `deny-hook.sh`).
#[derive(Debug, Clone, Default)]
pub struct GuardReport {
    pub hard_denies: Vec<String>,
    pub guard_hits: Vec<String>,
    pub root_wipe: bool,
    pub never_reasons: Vec<String>,
}

/// Format a hook decision identically to `deny-hook.sh`'s `decide()`.
/// Returns `(stdout_json_line, optional_stderr_line, exit_code)`.
pub fn format_decision(
    kind: DecisionKind,
    reason: &str,
    strict: bool,
    headless_strict: bool,
    goose_mode: bool,
) -> (String, Option<String>, i32) {
    let dec = match kind {
        DecisionKind::Ask if strict || headless_strict => "deny",
        DecisionKind::Ask => "ask",
        DecisionKind::Deny => "deny",
    };
    let top_dec = if dec == "deny" && goose_mode {
        "block"
    } else {
        dec
    };
    let obj = json!({
        "decision": top_dec,
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": dec,
            "permissionDecisionReason": reason,
        }
    });
    let line = serde_json::to_string(&obj).unwrap_or_else(|_| {
        format!(
            "{{\"decision\":\"{top_dec}\",\"reason\":\"denied by policy\",\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"{dec}\",\"permissionDecisionReason\":\"denied by policy\"}}}}"
        )
    });
    if dec == "deny" && strict {
        (line, Some(reason.to_string()), 2)
    } else {
        (line, None, 0)
    }
}

pub fn emit_decision(
    kind: DecisionKind,
    reason: &str,
    strict: bool,
    headless_strict: bool,
    goose_mode: bool,
) -> i32 {
    let (stdout_line, stderr_line, code) =
        format_decision(kind, reason, strict, headless_strict, goose_mode);
    println!("{stdout_line}");
    if let Some(err) = stderr_line {
        eprintln!("{err}");
    }
    code
}
