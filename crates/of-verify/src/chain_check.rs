//! Native Rust port of `runtime/scripts/chain_check.py`:
//! executable form of `mission-chaining.md`'s degraded-terminal rule.

use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEGRADED_SUFFIXES: &[&str] = &[
    "-WITH-PARKED",
    "-WITH-OPEN-ITEMS",
    "-WITH-GAPS",
    "-WITH-MANUAL-PARKED",
    "-WITH-BLOCKED",
    "-WITH-QUARANTINE",
    "-WITH-PINNED",
];

pub const DEGRADED_STANDALONE: &[&str] = &["NO-GO", "INCONCLUSIVE", "ABANDONED"];
pub const HANDOFF: &[&str] = &["AWAITING-MAINTAINER-MERGE"];
pub const HANDOFF_SUFFIX: &str = "-WITH-HANDOFF";

fn terminal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^- \*\*([A-Z][A-Z0-9-]*)\*\*(\s*\(degraded\b)?").expect("regex")
    })
}

fn sep_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[-_\s]+").expect("regex"))
}

fn terminal_shape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$").expect("regex"))
}

pub fn canonical(terminal: &str) -> String {
    let replaced = sep_re().replace_all(terminal.trim(), "-");
    replaced.trim_matches('-').to_ascii_uppercase()
}

pub fn classify(terminal: &str) -> &'static str {
    let name = canonical(terminal);
    if !terminal_shape_re().is_match(&name) {
        return "unknown";
    }
    if DEGRADED_STANDALONE.contains(&name.as_str())
        || DEGRADED_SUFFIXES.iter().any(|s| name.ends_with(s))
    {
        return "degraded";
    }
    if HANDOFF.contains(&name.as_str()) || name.ends_with(HANDOFF_SUFFIX) {
        return "handoff";
    }
    if format!("-{name}-").contains("-WITH-") {
        return "unknown";
    }
    "clean"
}

pub fn gate(terminal: &str, allowed: &BTreeSet<String>) -> (bool, String) {
    let cls = classify(terminal);
    if cls == "degraded" {
        return (
            false,
            format!("{terminal} is degraded — the chain stops and parks"),
        );
    }
    if cls == "unknown" {
        return (
            false,
            format!("{terminal:?} is not a recognised terminal — the chain stops (fail closed)"),
        );
    }
    let canon = canonical(terminal);
    let canon_allowed: BTreeSet<String> = allowed.iter().map(|a| canonical(a)).collect();
    if !canon_allowed.contains(&canon) {
        let mut sorted: Vec<&String> = allowed.iter().collect();
        sorted.sort();
        return (
            false,
            format!("{terminal} ({cls}) is not in the chain's allowed set {sorted:?}"),
        );
    }
    (true, format!("{terminal} ({cls}) is declared allowed"))
}

pub fn audit(root: &Path) -> Result<Vec<String>, String> {
    let skills = root.join("skills");
    let mut problems = Vec::new();
    if !skills.is_dir() {
        return Ok(problems);
    }
    let mut dirs: Vec<PathBuf> = fs::read_dir(&skills)
        .map_err(|e| format!("{}: {e}", skills.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let skill_md = dir.join("SKILL.md");
        if !skill_md.is_file() {
            continue;
        }
        let mname = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let text =
            fs::read_to_string(&skill_md).map_err(|e| format!("{}: {e}", skill_md.display()))?;
        for caps in terminal_re().captures_iter(&text) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let has_label = caps.get(2).is_some();
            let cls = classify(name);
            if cls == "unknown" {
                problems.push(format!(
                    "{mname}: {name} is not a terminal this rule classifies (an unknown -WITH- qualifier?)"
                ));
                continue;
            }
            if has_label && cls != "degraded" {
                problems.push(format!(
                    "{mname}: {name} is labelled (degraded) but classifies {cls}"
                ));
            }
            if cls == "degraded" && !has_label {
                problems.push(format!(
                    "{mname}: {name} classifies degraded but carries no (degraded) label"
                ));
            }
        }
    }
    Ok(problems)
}

pub fn cmd_classify(terminal: &str) -> i32 {
    let cls = classify(terminal);
    println!("{cls}");
    if cls == "unknown" {
        1
    } else {
        0
    }
}

pub fn cmd_gate(allowed_csv: &str, terminal: &str) -> i32 {
    let allowed: BTreeSet<String> = allowed_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let (proceed, why) = gate(terminal, &allowed);
    println!("{}: {why}", if proceed { "PROCEED" } else { "STOP" });
    if proceed {
        0
    } else {
        1
    }
}

pub fn cmd_audit(root: Option<&Path>) -> i32 {
    let resolved = match root {
        Some(r) => r.to_path_buf(),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            of_install::resolve_catalog_root(&cwd)
                .map(|(p, _)| p)
                .unwrap_or(cwd)
        }
    };
    match audit(&resolved) {
        Ok(problems) => {
            for p in &problems {
                eprintln!("{p}");
            }
            if !problems.is_empty() {
                return 1;
            }
            println!("chain-check: every declared terminal label agrees with the classification");
            0
        }
        Err(err) => {
            eprintln!("chain-check: {err}");
            1
        }
    }
}
