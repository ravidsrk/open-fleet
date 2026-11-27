//! Native Rust port of `runtime/scripts/proof_status.py`:
//! proof-posture reporter and CI lens over the mission catalog.

use of_catalog::frontmatter::parse_frontmatter;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const PROOF_TIERS: &[&str] = &["doctrine-only", "self-run", "external-run"];
const TIERS_REQUIRING_EVIDENCE: &[&str] = &["self-run", "external-run"];

#[derive(Debug, Clone, Serialize)]
pub struct ProofRecord {
    pub dir: String,
    pub name: Option<String>,
    pub proof: Option<String>,
    pub proof_evidence: Option<String>,
    pub evidence_resolves: bool,
    pub error: Option<String>,
}

pub fn collect(skills_dir: &Path, root: &Path) -> Vec<ProofRecord> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(skills_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let resolved_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut records = Vec::new();
    for skill_dir in dirs {
        let md = skill_dir.join("SKILL.md");
        if !md.is_file() {
            continue;
        }
        let dir_name = skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let mut rec = ProofRecord {
            dir: dir_name,
            name: None,
            proof: None,
            proof_evidence: None,
            evidence_resolves: false,
            error: None,
        };
        let text = match fs::read_to_string(&md) {
            Ok(t) => t,
            Err(err) => {
                rec.error = Some(format!("unreadable: {err}"));
                records.push(rec);
                continue;
            }
        };
        let data = match parse_frontmatter(&text) {
            Ok(d) => d,
            Err(err) => {
                rec.error = Some(err);
                records.push(rec);
                continue;
            }
        };
        rec.name = data
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(meta) = data.get("metadata").and_then(|v| v.as_map()) {
            rec.proof = meta
                .get("proof")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(ev) = meta.get("proof_evidence").and_then(|v| v.as_str()) {
                if !ev.is_empty() && ev != "<object>" {
                    rec.proof_evidence = Some(ev.to_string());
                    let joined = root.join(ev);
                    if let Ok(resolved_ev) = fs::canonicalize(&joined) {
                        rec.evidence_resolves =
                            resolved_ev.starts_with(&resolved_root) && resolved_ev.is_file();
                    }
                }
            }
        }
        records.push(rec);
    }
    records
}

pub fn rollup(records: &[ProofRecord]) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> =
        PROOF_TIERS.iter().map(|&t| (t, 0usize)).collect();
    for rec in records {
        if let Some(p) = rec.proof.as_deref() {
            if let Some(c) = counts.get_mut(p) {
                *c += 1;
            }
        }
    }
    counts.insert("total", records.len());
    counts
}

pub fn check_failures(records: &[ProofRecord]) -> Vec<&ProofRecord> {
    let mut failures = Vec::new();
    for rec in records {
        let tier = rec.proof.as_deref().unwrap_or("");
        let bad_tier = !PROOF_TIERS.contains(&tier);
        let missing_ev = TIERS_REQUIRING_EVIDENCE.contains(&tier)
            && (rec.proof_evidence.is_none() || !rec.evidence_resolves);
        if rec.error.is_some() || bad_tier || missing_ev {
            failures.push(rec);
        }
    }
    failures
}

pub fn format_report(records: &[ProofRecord]) -> String {
    let mut lines = Vec::new();
    let name_w = records
        .iter()
        .map(|r| r.name.as_deref().unwrap_or(&r.dir).len())
        .max()
        .unwrap_or(4);
    let tier_w = PROOF_TIERS.iter().map(|t| t.len()).max().unwrap_or(13);
    for rec in records {
        let name = rec.name.as_deref().unwrap_or(&rec.dir);
        let tier = rec.proof.as_deref().unwrap_or("?");
        let (mark, evidence): (&str, String) = if let Some(err) = &rec.error {
            ("ERROR", err.clone())
        } else if !PROOF_TIERS.contains(&tier) {
            (
                "INVALID",
                rec.proof_evidence
                    .clone()
                    .unwrap_or_else(|| "—".to_string()),
            )
        } else if let Some(ev) = &rec.proof_evidence {
            (
                if rec.evidence_resolves {
                    "ok"
                } else {
                    "MISSING"
                },
                ev.clone(),
            )
        } else {
            ("—", "—".to_string())
        };
        lines.push(format!(
            "{name:<name_w$}  {tier:<tier_w$}  [{mark:<7}] {evidence}"
        ));
    }
    let counts = rollup(records);
    lines.push(String::new());
    lines.push("coverage rollup:".to_string());
    for &tier in PROOF_TIERS {
        let c = counts.get(tier).copied().unwrap_or(0);
        lines.push(format!("  {tier:<tier_w$}  {c}"));
    }
    let total = counts.get("total").copied().unwrap_or(0);
    lines.push(format!("  {:<tier_w$}  {total}", "total"));
    lines.join("\n")
}

pub fn json_records(records: &[ProofRecord]) -> Value {
    let arr: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "proof": r.proof,
                "proof_evidence": r.proof_evidence,
                "evidence_resolves": r.evidence_resolves,
                "error": r.error,
            })
        })
        .collect();
    Value::Array(arr)
}

pub struct ProofStatusArgs {
    pub json: bool,
    pub check: bool,
    pub root: Option<PathBuf>,
}

pub fn run_cli(args: &ProofStatusArgs) -> i32 {
    let root = match &args.root {
        Some(r) => fs::canonicalize(r).unwrap_or_else(|_| r.clone()),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            of_install::find_catalog_root(&cwd).unwrap_or(cwd)
        }
    };
    let skills_dir = root.join("skills");
    if !skills_dir.is_dir() {
        eprintln!("no skills/ directory under {}", root.display());
        return 1;
    }
    let records = collect(&skills_dir, &root);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_records(&records))
                .unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        println!("{}", format_report(&records));
    }
    if args.check {
        let failures = check_failures(&records);
        if !failures.is_empty() {
            for rec in &failures {
                let name = rec.name.as_deref().unwrap_or(&rec.dir);
                if let Some(err) = &rec.error {
                    eprintln!("FAIL: {name} — parse error: {err}");
                } else {
                    let tier = rec.proof.as_deref().unwrap_or("");
                    if !PROOF_TIERS.contains(&tier) {
                        eprintln!(
                            "FAIL: {name} ({:?}) — invalid or missing proof tier (want {})",
                            rec.proof,
                            PROOF_TIERS.join("|")
                        );
                    } else {
                        let why = if rec.proof_evidence.is_none() {
                            "no proof_evidence"
                        } else {
                            "unresolvable proof_evidence"
                        };
                        eprintln!(
                            "FAIL: {name} ({tier}) — {why}: {}",
                            rec.proof_evidence.as_deref().unwrap_or("—")
                        );
                    }
                }
            }
            eprintln!(
                "proof-status: {} mission(s) failed proof-status checks",
                failures.len()
            );
            return 1;
        }
    }
    0
}
