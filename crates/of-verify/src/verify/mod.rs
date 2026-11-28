//! Independent evidence-manifest verifier — native Rust port of `runtime/scripts/verify.py`.
//! Re-derives scope, commit identity, review authority, negative control execution,
//! commands ledger, redaction, provenance, retention receipts, and signed transcripts.

pub mod authority;
pub mod diff;
pub mod execute_nc;
pub mod sig;

use crate::base64_codec::{decode_strict, encode as b64_encode};
use crate::diff_scope::is_test_path;
use crate::dispatch_sign::{
    canonical_record, publickey_bytes, read_seed, sign_bytes, verify_bytes, RECORD_FIELDS,
    TOOLCHAIN_FILES, TRANSCRIPT_FIELDS,
};
use crate::inventory::{
    find_signature, parse_receipt, resolve_entry, signer_id, verify_signature, RECEIPT_FIELDS,
    RECEIPT_SCHEMA,
};
use authority::{
    pathlib_posix, run_proc_bytes, sha256_hex, unreplayable_tool, VerifyCtx,
    INDEPENDENT_REVIEWER_ASSOCIATIONS, SCRUB_NOTE, SOUND_PROVENANCE,
};
use chrono::{SecondsFormat, Utc};
use diff::{
    bind_hunks_to_change, diff_target_paths, extract_diff, hunk_lines, is_hex40,
    iter_diff_target_paths, nc_paths, shlex_join, shlex_split, Coord,
};
use execute_nc::execute_negative_control;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const UNIT_CLASSES: &[&str] = &["mutation", "report-only", "planning"];
pub const NC_TOOLS: &[&str] = &[
    "mutmut",
    "cosmic-ray",
    "stryker",
    "pitest",
    "cargo-mutants",
    "go-mutesting",
    "revert",
    "hand",
];
pub const REVIEWER_MODES: &[&str] = &["cross-vendor", "same-vendor-fresh", "instructed-isolation"];
pub const LIGHTING_VALUES: &[&str] = &["lit", "dark-eligible"];
pub const EXECUTABLE_NC_TOOLS: &[&str] = &[
    "revert",
    "hand",
    "mutmut",
    "cosmic-ray",
    "stryker",
    "pitest",
    "cargo-mutants",
    "go-mutesting",
];
const PROSE_SUFFIXES: &[&str] = &[".md", ".markdown", ".rst", ".txt", ".adoc", ".org"];

fn crit_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^[ \t]*(?:[-*]|\d+\.)?[ \t]*((?:[A-Z][A-Z0-9]*-\d+)|(?:[A-Z]{2,}\d+))[ \t]*[:.)]",
        )
        .expect("regex")
    })
}

fn crit_shaped_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b((?:[A-Z][A-Z0-9]*-\d+)|(?:[A-Z]{2,}\d+))\b").expect("regex"))
}

fn redaction_patterns() -> &'static Vec<(&'static str, Regex)> {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            (
                "aws-access-key",
                Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("re"),
            ),
            (
                "github-token",
                Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b").expect("re"),
            ),
            (
                "github-pat",
                Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").expect("re"),
            ),
            (
                "private-key-block",
                Regex::new(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----").expect("re"),
            ),
            (
                "slack-token",
                Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").expect("re"),
            ),
            (
                "inline-credential",
                Regex::new(r#"(?i)\b(?:password|passwd|secret)\s*=\s*["']?[^\s"';,)}<]{6,}"#)
                    .expect("re"),
            ),
        ]
    })
}

fn nc_zero_kill_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(not\s+killed|not\s+red|\bno\s+mutants?\s+killed\b|killed\s*[:=]\s*0\b",
            r"|\b0(?:\.0+)?\s*%\s+killed\b|\b0\s+mutants?\s+killed\b|\b0\s+killed\b)",
        ))
        .expect("re")
    })
}

fn nc_killed_word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(killed|red)\b").expect("re"))
}

fn nc_negated_kill_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\bnot\b|\bnever\b|n't\b)[^.;]{0,20}\b(?:killed|red)\b").expect("re")
    })
}

fn nc_artifact_kill_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(killed|red|fail)\b").expect("re"))
}

fn has_survived_nonzero(content: &str, prefix_re: &Regex) -> bool {
    // Emulates `survived\b(?![\s:=-]*0\b)` without lookahead.
    for m in prefix_re.find_iter(content) {
        let after = &content[m.end()..];
        let trimmed =
            after.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, ':' | '=' | '-'));
        let zero_follow = trimmed.starts_with('0')
            && trimmed
                .as_bytes()
                .get(1)
                .map(|&b| !b.is_ascii_alphanumeric() && b != b'_')
                .unwrap_or(true);
        if !zero_follow {
            return true;
        }
    }
    false
}

pub struct EvidenceManifest {
    pub data: Value,
    pub raw: Vec<u8>,
    pub path: Option<String>,
    pub artifact_bytes: HashMap<String, Result<Vec<u8>, String>>,
    pub oracle_scope: Option<Value>,
}

pub fn load_manifest(path: &str) -> Result<EvidenceManifest, String> {
    let raw = fs::read(path).map_err(|e| format!("unreadable/invalid manifest: {e}"))?;
    let val: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("unreadable/invalid manifest: {e}"))?;
    if !val.is_object() {
        return Err(format!(
            "manifest must be a JSON object, got {}",
            json_type_name(&val)
        ));
    }
    Ok(EvidenceManifest {
        data: val,
        raw,
        path: Some(path.to_string()),
        artifact_bytes: HashMap::new(),
        oracle_scope: None,
    })
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

pub fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn norm_digest(d: &str) -> String {
    if d.starts_with("sha256:") {
        d.to_string()
    } else {
        format!("sha256:{d}")
    }
}

pub fn artifact_inventory(m: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(arr) = m.get("artifacts").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(obj) = entry.as_object() {
                if let (Some(p), Some(d)) = (
                    obj.get("path").and_then(|v| v.as_str()),
                    obj.get("sha256").and_then(|v| v.as_str()),
                ) {
                    let norm = d.trim().to_ascii_lowercase();
                    let stripped = norm.strip_prefix("sha256:").unwrap_or(&norm).to_string();
                    out.insert(p.to_string(), stripped);
                }
            }
        }
    }
    out
}

pub fn read_artifact(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    path: &str,
) -> Result<Vec<u8>, String> {
    if let Some(cached) = m.artifact_bytes.get(path) {
        return cached.clone();
    }
    let res = read_artifact_uncached(ctx, &m.data, path);
    m.artifact_bytes.insert(path.to_string(), res.clone());
    res
}

fn read_artifact_uncached(ctx: &mut VerifyCtx, m: &Value, path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("missing".to_string());
    }
    if path.contains('@') {
        return Err("artifact must be a repo-relative path, not a path@ref (#267)".to_string());
    }
    let (resolved_opt, err) = ctx.resolve_evidence(path);
    if let Some(e) = err {
        return Err(e);
    }
    let resolved = resolved_opt.expect("resolved");
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    let split = ctx.roots_are_split();
    let spelled = pathlib_posix(path);
    if !split && is_hex40(head) {
        let spec = format!("{head}:{spelled}");
        let (tc, ty) = ctx.git_str(&["cat-file", "-t", &spec], 10);
        if tc == 0 && ty == "blob" {
            let (code, out, gerr) = ctx.git_bytes(&["show", &spec], 20);
            if code != 0 {
                let msg = gerr.trim();
                return Err(if msg.is_empty() {
                    "cannot read the tracked artifact at head_sha".to_string()
                } else {
                    msg.to_string()
                });
            }
            let blob = sha256_hex(&out);
            if let Some(pinned) = artifact_inventory(m).get(path) {
                if !pinned.is_empty() && &blob != pinned {
                    return Err(format!(
                        "artifact '{path}' is tracked at head_sha as {blob} but artifacts[] pins {pinned} — a declared pin must bind the blob the verifier reads (#596)"
                    ));
                }
            }
            return Ok(out);
        }
    }
    let raw = fs::read(&resolved).map_err(|e| e.to_string())?;
    let inv = artifact_inventory(m);
    let Some(want) = inv.get(path).filter(|s| !s.is_empty()) else {
        let why = if split {
            "is not pinned by a sha256 in the manifest's artifacts[] integrity inventory — under split roots the SHA repository is never consulted for evidence bytes (#442)"
        } else {
            "is neither tracked at head_sha nor pinned by a sha256 in the manifest's artifacts[] integrity inventory"
        };
        return Err(format!(
            "artifact '{path}' {why} — unpinned evidence (#267)"
        ));
    };
    let got = sha256_hex(&raw);
    if &got != want {
        return Err(format!(
            "artifact '{path}' hashes {got} but artifacts[] pins {want} — the evidence changed after it was inventoried (#267)"
        ));
    }
    Ok(raw)
}

fn criterion_family(token: &str) -> &str {
    if let Some((head, _)) = token.rsplit_once('-') {
        head
    } else {
        token.trim_end_matches(|c: char| c.is_ascii_digit())
    }
}

fn hidden_criterion_ids(content: &str, counted: &BTreeSet<String>) -> BTreeMap<String, usize> {
    let prefixes: HashSet<&str> = counted.iter().map(|c| criterion_family(c)).collect();
    let mut hidden: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let ln = idx + 1;
        for caps in crit_shaped_re().captures_iter(line) {
            let tok = &caps[1];
            if counted.contains(tok) {
                continue;
            }
            if prefixes.contains(criterion_family(tok)) {
                hidden.entry(tok.to_string()).or_insert(ln);
            }
        }
    }
    hidden
}

fn json_contract(content: &str) -> Result<Option<Value>, String> {
    let Ok(data) = serde_json::from_str::<Value>(content) else {
        return Ok(None);
    };
    if let Some(arr) = data.get("criterion_ids").and_then(|v| v.as_array()) {
        for x in arr {
            if !x.is_string() {
                let snippet: String = x.to_string().chars().take(60).collect();
                return Err(format!(
                    "the authoritative contract's criterion_ids must hold only criterion-id strings, got {snippet} ({})",
                    json_type_name(x)
                ));
            }
        }
        return Ok(Some(data));
    }
    Ok(None)
}

fn extract_criterion_ids(content: &str) -> Result<BTreeSet<String>, String> {
    if let Some(doc) = json_contract(content)? {
        let ids: BTreeSet<String> = doc["criterion_ids"]
            .as_array()
            .expect("arr")
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        return Ok(ids);
    }
    let ids: BTreeSet<String> = crit_id_re()
        .captures_iter(content)
        .map(|c| c[1].to_string())
        .collect();
    Ok(ids)
}

fn is_mutation(unit_class: Option<&str>) -> bool {
    !matches!(unit_class, Some("report-only") | Some("planning"))
}

fn check_scope(
    ctx: &VerifyCtx,
    m: &Value,
    auth_source: Option<&str>,
    auth_digest: Option<&str>,
) -> Vec<String> {
    let (Some(src), Some(dig)) = (
        auth_source.filter(|s| !s.is_empty()),
        auth_digest.filter(|s| !s.is_empty()),
    ) else {
        return vec![
            "scope: no authoritative contract (--contract-source/--contract-digest from the dispatch record) — a worker manifest cannot certify its own denominator".to_string(),
        ];
    };
    let (content_opt, err) = ctx.read_source(src);
    if let Some(e) = err {
        return vec![format!(
            "scope: authoritative contract unreadable ({src}): {e}"
        )];
    }
    let content = content_opt.expect("bytes");
    let want = norm_digest(dig);
    let got = sha256_of(&content);
    if got != want {
        return vec![format!(
            "scope: authoritative source does not match --contract-digest ({got} != {want})"
        )];
    }
    let text = match std::str::from_utf8(&content) {
        Ok(t) => t,
        Err(e) => return vec![format!("scope: authoritative contract is not UTF-8: {e}")],
    };
    let authoritative = match extract_criterion_ids(text) {
        Ok(ids) => ids,
        Err(e) => return vec![format!("scope: {e}")],
    };
    if authoritative.is_empty() {
        return vec!["scope: no criterion ids in the authoritative contract".to_string()];
    }
    if let Ok(Some(doc)) = json_contract(text) {
        let mut listed = BTreeSet::new();
        if let Some(arr) = doc.get("criteria").and_then(|v| v.as_array()) {
            for c in arr {
                if let Some(id) = c.get("id").and_then(|v| v.as_str()) {
                    listed.insert(id.to_string());
                }
            }
        }
        let undeclared: Vec<&String> = listed.difference(&authoritative).collect();
        if !undeclared.is_empty() {
            let auth_v: Vec<&String> = authoritative.iter().collect();
            return vec![format!(
                "scope: the authoritative contract lists {undeclared:?} in its criteria[] but leaves them out of criterion_ids, so the denominator would be {auth_v:?} — smaller than the contract a human reads, which is the whole scope guarantee. Declare every criterion in criterion_ids (#296)"
            )];
        }
    } else {
        let hidden = hidden_criterion_ids(text, &authoritative);
        if !hidden.is_empty() {
            let where_s: String = hidden
                .iter()
                .map(|(tok, ln)| format!("{tok} (line {ln})"))
                .collect::<Vec<_>>()
                .join(", ");
            let auth_v: Vec<&String> = authoritative.iter().collect();
            return vec![format!(
                "scope: the authoritative contract carries {where_s} in a form the extractor does not count, beside criteria it does. The denominator would be {auth_v:?} — smaller than the contract a human reads, which is the whole scope guarantee. Write every criterion as a list item (`- AC-2: …`), or use a JSON contract with an explicit criterion_ids array (#296)"
            )];
        }
    }

    let empty_obj = Value::Object(Map::new());
    let contract_v = match m.get("contract") {
        None | Some(Value::Null) => &empty_obj,
        Some(v) => v,
    };
    let Some(contract) = contract_v.as_object() else {
        return vec![format!(
            "scope: manifest `contract` must be an object, got {}",
            json_type_name(contract_v)
        )];
    };
    if let Some(d_val) = contract.get("digest") {
        if !d_val.is_null() && !d_val.is_string() {
            return vec![format!(
                "scope: manifest contract.digest must be a string, got {}",
                json_type_name(d_val)
            )];
        }
    }
    let declared: BTreeSet<String> = match contract.get("criterion_ids") {
        None | Some(Value::Null) => BTreeSet::new(),
        Some(Value::Array(arr)) => {
            if !arr.iter().all(|x| x.is_string()) {
                let s: String = Value::Array(arr.clone())
                    .to_string()
                    .chars()
                    .take(60)
                    .collect();
                return vec![format!(
                    "scope: manifest contract.criterion_ids must be a list of criterion-id strings, got {s}"
                )];
            }
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        }
        Some(other) => {
            let s: String = other.to_string().chars().take(60).collect();
            return vec![format!(
                "scope: manifest contract.criterion_ids must be a list of criterion-id strings, got {s}"
            )];
        }
    };
    let empty_arr = Vec::new();
    let criteria: &Vec<Value> = match m.get("criteria") {
        None | Some(Value::Null) => &empty_arr,
        Some(Value::Array(arr)) => arr,
        Some(other) => {
            return vec![format!(
                "scope: manifest `criteria` must be a list of {{id, addressed}} objects, got {}",
                json_type_name(other)
            )];
        }
    };
    for (i, item) in criteria.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            let s: String = item.to_string().chars().take(60).collect();
            return vec![format!(
                "scope: manifest criteria[{i}] must be an {{id, addressed}} object, got {s} ({})",
                json_type_name(item)
            )];
        };
        if !obj.get("id").map(|v| v.is_string()).unwrap_or(false) {
            let s: String = obj
                .get("id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string())
                .chars()
                .take(60)
                .collect();
            return vec![format!(
                "scope: manifest criteria[{i}].id must be a criterion-id string, got {s}"
            )];
        }
    }

    let mut errs = Vec::new();
    if let Some(mdigest) = contract.get("digest").and_then(|v| v.as_str()) {
        if !mdigest.is_empty() && norm_digest(mdigest) != want {
            errs.push(
                "scope: manifest contract.digest != authoritative digest (denominator swap)"
                    .to_string(),
            );
        }
    }
    let addressed: BTreeSet<String> = criteria
        .iter()
        .filter(|c| c.get("addressed") == Some(&Value::Bool(true)))
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    let unaddressed: Vec<&String> = authoritative.difference(&addressed).collect();
    if !unaddressed.is_empty() {
        errs.push(format!(
            "scope: authoritative criteria not addressed in criteria[] (absent, or addressed != true): {}",
            py_repr_list(&unaddressed)
        ));
    }
    let undeclared: Vec<&String> = authoritative.difference(&declared).collect();
    if !undeclared.is_empty() {
        errs.push(format!(
            "scope shrunk: contract.criterion_ids drops authoritative ids: {}",
            py_repr_list(&undeclared)
        ));
    }
    errs
}

fn py_repr_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn py_repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

fn py_repr_val(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => py_repr_str(s),
        Some(Value::Array(arr)) => {
            let parts: Vec<String> = arr.iter().map(|x| py_repr_val(Some(x))).collect();
            format!("[{}]", parts.join(", "))
        }
        Some(other) => other.to_string(),
    }
}

fn check_shas_present(m: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    for field in ["base_sha", "head_sha"] {
        let ok = m
            .get(field)
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !ok {
            errs.push(format!("missing required '{field}'"));
        }
    }
    errs
}

fn check_real_commits(ctx: &VerifyCtx, m: &Value, is_mut: bool) -> Vec<String> {
    let mut errs = Vec::new();
    for field in ["base_sha", "head_sha"] {
        if let Some(sha) = m.get(field).and_then(|v| v.as_str()) {
            if !sha.is_empty() && !is_hex40(sha) {
                let msg = format!(
                    "{field} '{sha}' is not a pinned 40-hex commit SHA (a symbolic ref is not immutable)"
                );
                errs.push(if is_mut { msg } else { format!("NOTE: {msg}") });
            }
        }
    }
    if ctx.git_str(&["rev-parse", "--is-inside-work-tree"], 10).0 != 0 {
        errs.push("NOTE: not inside a git repo — commit-existence check skipped".to_string());
        return errs;
    }
    for field in ["base_sha", "head_sha"] {
        if let Some(sha) = m.get(field).and_then(|v| v.as_str()) {
            if sha.is_empty() {
                continue;
            }
            if sha.starts_with('-') {
                errs.push(format!(
                    "{field} {sha:?} is option-shaped — refusing before git sees it"
                ));
                continue;
            }
            let spec = format!("{sha}^{{commit}}");
            if ctx.git_str(&["cat-file", "-e", &spec], 10).0 != 0 {
                errs.push(format!("{field} '{sha}' is not a real commit"));
            }
        }
    }
    errs
}

fn wtree_bound(ctx: &VerifyCtx, m: &Value) -> bool {
    let Some(pr) = m.get("pr").and_then(|v| v.as_object()) else {
        return false;
    };
    let reviewed = pr
        .get("reviewed_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    let wtree = pr
        .get("reviewed_wtree")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !is_hex40(reviewed) || !is_hex40(head) || !is_hex40(wtree) {
        return false;
    }
    if ctx.git_str(&["rev-parse", "--is-inside-work-tree"], 10).0 != 0 {
        return false;
    }
    let (Some(rt), Some(ht)) = (ctx.tree_of(reviewed), ctx.tree_of(head)) else {
        return false;
    };
    rt == wtree && ht == wtree
}

fn check_freshness(ctx: &VerifyCtx, m: &Value) -> Vec<String> {
    let reviewed = m
        .get("pr")
        .and_then(|v| v.get("reviewed_sha"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    if !reviewed.is_empty() && reviewed != head && !wtree_bound(ctx, m) {
        return vec![format!(
            "stale review: reviewed_sha '{reviewed}' != head_sha '{head}'"
        )];
    }
    Vec::new()
}

pub fn parse_review_pages(out: &str) -> Result<Vec<Value>, String> {
    let mut items = Vec::new();
    let mut slice = out.trim_start();
    while !slice.is_empty() {
        let mut de = serde_json::Deserializer::from_str(slice).into_iter::<Value>();
        match de.next() {
            Some(Ok(Value::Array(arr))) => {
                items.extend(arr);
                let consumed = de.byte_offset();
                slice = slice[consumed..].trim_start();
            }
            Some(Ok(_)) => return Err("unexpected non-array page in gh output".to_string()),
            Some(Err(e)) => return Err(e.to_string()),
            None => break,
        }
    }
    Ok(items)
}

fn review_ok(
    reviews: &[Value],
    head_sha: &str,
    author: Option<&str>,
    also_sha: Option<&str>,
    equivalent_shas: &HashSet<String>,
) -> bool {
    let mut ok_shas: HashSet<&str> = HashSet::new();
    ok_shas.insert(head_sha);
    if let Some(a) = also_sha {
        ok_shas.insert(a);
    }
    let mut relevant: HashSet<&str> = ok_shas.clone();
    for s in equivalent_shas {
        relevant.insert(s.as_str());
    }
    let mut latest: HashMap<String, &Value> = HashMap::new();
    for r in reviews {
        let cid = r.get("commit_id").and_then(|v| v.as_str()).unwrap_or("");
        if relevant.contains(cid) {
            let login = r
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            latest.insert(login, r);
        }
    }
    let independent: Vec<&Value> = latest
        .iter()
        .filter(|(who, _)| author.map(|a| who.as_str() != a).unwrap_or(true))
        .map(|(_, r)| *r)
        .collect();
    if independent
        .iter()
        .any(|r| r.get("state").and_then(|v| v.as_str()) == Some("CHANGES_REQUESTED"))
    {
        return false;
    }
    independent.iter().any(|r| {
        let state_ok = r.get("state").and_then(|v| v.as_str()) == Some("APPROVED");
        let cid = r.get("commit_id").and_then(|v| v.as_str()).unwrap_or("");
        let assoc = r
            .get("author_association")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        state_ok && ok_shas.contains(cid) && INDEPENDENT_REVIEWER_ASSOCIATIONS.contains(&assoc)
    })
}

fn equivalent_review_shas(
    ctx: &VerifyCtx,
    reviews: &[Value],
    head: &str,
    author: &str,
    also_sha: Option<&str>,
) -> Result<HashSet<String>, String> {
    let mut known: HashSet<String> = HashSet::new();
    known.insert(head.to_string());
    if let Some(a) = also_sha {
        known.insert(a.to_string());
    }
    let mut settled: HashSet<String> = HashSet::new();
    let mut trees: HashMap<String, Option<String>> = HashMap::new();
    for review in reviews.iter().rev() {
        let who = review
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if who == author || settled.contains(who) {
            continue;
        }
        let sha = review
            .get("commit_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !known.contains(sha) {
            if !trees.contains_key(head) {
                trees.insert(head.to_string(), ctx.tree_of(head));
            }
            let head_tree = match trees.get(head).and_then(|o| o.as_ref()) {
                Some(t) => t.clone(),
                None => {
                    return Err(
                        "cannot resolve head tree for authoritative review history".to_string()
                    );
                }
            };
            if !trees.contains_key(sha) {
                let t = if is_hex40(sha) {
                    ctx.tree_of(sha)
                } else {
                    None
                };
                trees.insert(sha.to_string(), t);
            }
            let sha_tree = match trees.get(sha).and_then(|o| o.as_ref()) {
                Some(t) => t.clone(),
                None => {
                    return Err(format!(
                        "cannot resolve historical review commit {sha:?}; fail-closed"
                    ));
                }
            };
            if sha_tree != head_tree {
                continue;
            }
            known.insert(sha.to_string());
        }
        settled.insert(who.to_string());
    }
    Ok(known)
}

fn quiet_oss_authorized(ctx: &VerifyCtx, source: Option<&str>, digest: Option<&str>) -> bool {
    let (Some(src), Some(dig)) = (source, digest) else {
        return false;
    };
    let (Some(raw), None) = ctx.read_source(src) else {
        return false;
    };
    if sha256_of(&raw) != norm_digest(dig) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&raw) else {
        return false;
    };
    let Ok(Some(doc)) = json_contract(text) else {
        return false;
    };
    doc.get("mission").and_then(|v| v.as_str()) == Some("oss-contribute")
        || doc.get("allow_quiet_oss") == Some(&Value::Bool(true))
}

struct QuietOssCtx<'a> {
    reviews: &'a [Value],
    head: &'a str,
    author: &'a str,
    equivalent: Option<&'a str>,
    review_shas: &'a HashSet<String>,
    corroborated: bool,
    nc_executed: bool,
    oss_authorized: bool,
}

fn quiet_oss_review(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    q: &QuietOssCtx<'_>,
) -> (bool, Vec<String>) {
    let QuietOssCtx {
        reviews,
        head,
        author,
        equivalent,
        review_shas,
        corroborated,
        nc_executed,
        oss_authorized,
    } = *q;
    if !oss_authorized {
        return (false, Vec::new());
    }
    let is_quiet_oss = m
        .data
        .get("parked")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|p| {
                p.get("reason").and_then(|v| v.as_str()) == Some("awaiting-maintainer-merge")
            })
        })
        .unwrap_or(false);
    if !is_quiet_oss {
        return (false, Vec::new());
    }
    let mut relevant: HashSet<&str> = review_shas.iter().map(|s| s.as_str()).collect();
    relevant.insert(head);
    if let Some(eq) = equivalent {
        relevant.insert(eq);
    }
    let mut latest: HashMap<String, &Value> = HashMap::new();
    for rev in reviews {
        let cid = rev.get("commit_id").and_then(|v| v.as_str()).unwrap_or("");
        if relevant.contains(cid) {
            let login = rev
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            latest.insert(login, rev);
        }
    }
    if latest
        .iter()
        .filter(|(who, _)| who.as_str() != author)
        .any(|(_, r)| r.get("state").and_then(|v| v.as_str()) == Some("CHANGES_REQUESTED"))
    {
        return (false, Vec::new());
    }
    let art = m
        .data
        .get("review")
        .and_then(|v| v.get("artifact"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if art.is_empty() {
        return (false, Vec::new());
    }
    let Ok(raw) = read_artifact(ctx, m, &art) else {
        return (false, Vec::new());
    };
    if !head.is_empty() && !String::from_utf8_lossy(&raw).contains(head) {
        return (false, Vec::new());
    }
    if !corroborated || !nc_executed {
        return (false, Vec::new());
    }
    (
        true,
        vec![
            "NOTE: oss-contribute quiet PR (awaiting-maintainer-merge) — coordinator contract authorizes oss-contribute, no upstream CHANGES_REQUESTED veto, internal review.artifact bound to head_sha, and negative control EXECUTED".to_string(),
        ],
    )
}

struct ReviewOpts<'a> {
    repo: Option<&'a str>,
    is_mut: bool,
    no_gh: bool,
    corroborated: bool,
    dispatch_lighting: Option<&'a str>,
    nc_executed: bool,
    allow_static_nc: bool,
    oss_authorized: bool,
}

fn check_review(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    opts: &ReviewOpts<'_>,
) -> Vec<String> {
    let ReviewOpts {
        repo,
        is_mut,
        no_gh,
        corroborated,
        dispatch_lighting,
        nc_executed,
        allow_static_nc,
        oss_authorized,
    } = *opts;
    if !is_mut {
        return Vec::new();
    }
    let waiver_msg = |lane: &str| {
        format!(
            "{lane}: the independent review is WAIVED in this lane, so the negative control is the ONLY oracle left — and a control that was merely READ is a text file the worker wrote. It must be EXECUTED (--execute-nc / ORCA_EXECUTE_NC) and go RED. Fail-closed (#256; docs/reviews/2026-09-10-review.md A1/A2/A4/A6/A9 all landed on exactly this)"
        )
    };
    if dispatch_lighting == Some("dark-eligible") {
        if !corroborated {
            return vec![
                "dark-eligible mutation: review is waived, so the negative-control oracle must be unfakeable — but without an out-of-band coordinator contract (--contract-source + --contract-digest) the worker-produced artifact is forgeable; fail-closed (gate-classification.md)".to_string(),
            ];
        }
        if !nc_executed {
            return vec![waiver_msg("dark-eligible mutation")];
        }
        return vec![
            "NOTE: independent review waived — dark-eligible unit (gate-classification.md); the EXECUTED negative control + tests are the oracle, not a human review".to_string(),
        ];
    }
    let head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if no_gh {
        let art = m
            .data
            .get("review")
            .and_then(|v| v.get("artifact"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if art.is_empty() {
            return vec![
                "no-gh mutation unit: missing review.artifact (a local reviewer record at head_sha)"
                    .to_string(),
            ];
        }
        let content = match read_artifact(ctx, m, &art) {
            Ok(b) => b,
            Err(e) => {
                return vec![format!(
                    "no-gh mutation unit: review.artifact unreadable ({art}): {e}"
                )];
            }
        };
        if !head.is_empty() && !String::from_utf8_lossy(&content).contains(&head) {
            return vec![
                "no-gh mutation unit: review.artifact does not reference head_sha".to_string(),
            ];
        }
        if !corroborated {
            return vec![
                "no-gh mutation unit: review.artifact is worker-forgeable without an out-of-band coordinator contract (--contract-source + --contract-digest) — fail-closed (sign the dispatch record; merge-serialization.md)".to_string(),
            ];
        }
        if !nc_executed {
            return vec![waiver_msg("no-gh mutation unit")];
        }
        return vec![
            "NOTE: no-gh review is coordinator-attested via the frozen out-of-band contract (local reviewer artifact at head_sha) plus an EXECUTED negative control, not GitHub-verified — the weaker guarantee (merge-serialization.md)".to_string(),
        ];
    }

    let pr_num_val = m.data.get("pr").and_then(|v| v.get("number"));
    let Some(num_v) = pr_num_val else {
        return vec![
            "mutation unit: no pr.number to look up an independent review — unreviewed".to_string(),
        ];
    };
    if num_v.is_null()
        || num_v == &Value::Number(0.into())
        || num_v == &Value::Bool(false)
        || num_v == &Value::String(String::new())
    {
        return vec![
            "mutation unit: no pr.number to look up an independent review — unreviewed".to_string(),
        ];
    }
    let number = match num_v.as_i64() {
        Some(n) if n > 0 && !num_v.is_boolean() => n,
        _ => {
            return vec![format!(
                "mutation unit: pr.number {} is not a positive integer — it names the GitHub resource the review is read from, so anything else is refused; fail-closed",
                py_repr_val(Some(num_v))
            )];
        }
    };
    let Some(repo_s) = repo.filter(|s| !s.is_empty()) else {
        return vec![
            "mutation unit: --repo not resolvable — cannot verify the review independently"
                .to_string(),
        ];
    };
    let authority = ctx.review_leg(repo_s);
    if authority.iter().any(|l| !l.starts_with("NOTE:")) {
        return authority;
    }

    let (code, out, err) = ctx.gh_api(
        repo_s,
        &format!("pulls/{number}/reviews"),
        &["--paginate"],
        60,
    );
    let reviews = if code != 0 {
        let msg = err.trim();
        let why = if msg.is_empty() { "gh api failed" } else { msg };
        let scrub = if ctx.gh_custody.as_deref() == Some("absent") {
            ""
        } else {
            SCRUB_NOTE
        };
        let mut res = authority;
        res.push(format!(
            "mutation unit: cannot fetch reviews for {repo_s}#{number} ({why}) — fail-closed{scrub}"
        ));
        return res;
    } else {
        match parse_review_pages(&out) {
            Ok(list) => list,
            Err(why) => {
                let scrub = if ctx.gh_custody.as_deref() == Some("absent") {
                    ""
                } else {
                    SCRUB_NOTE
                };
                let mut res = authority;
                res.push(format!(
                    "mutation unit: cannot fetch reviews for {repo_s}#{number} ({why}) — fail-closed{scrub}"
                ));
                return res;
            }
        }
    };

    let (acode, aout, _) = ctx.gh_api(repo_s, &format!("pulls/{number}"), &[], 20);
    let author = if acode == 0 {
        serde_json::from_str::<Value>(&aout).ok().and_then(|v| {
            v.get("user")
                .and_then(|u| u.get("login"))
                .and_then(|l| l.as_str())
                .map(|s| s.to_string())
        })
    } else {
        None
    };
    let Some(author_s) = author else {
        return vec![format!(
            "mutation unit: cannot resolve PR author for {repo_s}#{number} — cannot exclude the author's self-review, fail-closed"
        )];
    };

    let equivalent = if wtree_bound(ctx, &m.data) {
        m.data
            .get("pr")
            .and_then(|v| v.get("reviewed_sha"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };
    let review_shas =
        match equivalent_review_shas(ctx, &reviews, &head, &author_s, equivalent.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                return vec![format!(
                    "mutation unit: cannot establish INDEPENDENT APPROVED review: {e}"
                )];
            }
        };
    if !review_ok(
        &reviews,
        &head,
        Some(&author_s),
        equivalent.as_deref(),
        &review_shas,
    ) {
        let (oss_ok, oss_notes) = quiet_oss_review(
            ctx,
            m,
            &QuietOssCtx {
                reviews: &reviews,
                head: &head,
                author: &author_s,
                equivalent: equivalent.as_deref(),
                review_shas: &review_shas,
                corroborated,
                nc_executed,
                oss_authorized,
            },
        );
        if oss_ok {
            let mut res = authority;
            res.extend(oss_notes);
            return res;
        }
        return vec![format!(
            "mutation unit: no INDEPENDENT APPROVED review at head_sha on {repo_s}#{number} (the PR author's own approval, superseded reviews, and approvals from accounts whose author_association is not one of ['COLLABORATOR', 'MEMBER', 'OWNER'] do not count; a review at reviewed_sha only counts when reviewed_wtree binds its tree to the head's)"
        )];
    }
    if !nc_executed && !allow_static_nc {
        let mut res = authority;
        res.push(
            "mutation unit: negative control was NOT executed — pass --execute-nc (and --nc-command) so the control is re-run, or pass --allow-static-nc to accept artifact-only corroboration explicitly (#750 C10)".to_string(),
        );
        return res;
    }
    authority
}

pub fn nc_command_argv(
    ctx: &VerifyCtx,
    nc: &Value,
    override_cmd: Option<&str>,
) -> Result<Vec<String>, String> {
    let raw = nc.get("command").and_then(|v| v.as_str()).unwrap_or("");
    if raw.trim().is_empty() {
        return Err(
            "negative_control.command (the criterion-bound proof command, as a string) is REQUIRED to execute the control — without it there is nothing to turn RED"
                .to_string(),
        );
    }
    let argv = shlex_split(raw, false).map_err(|e| {
        format!("negative_control.command is not parseable as a command line ({e})")
    })?;
    if argv.is_empty() {
        return Err("negative_control.command is empty after parsing".to_string());
    }
    let line = shlex_join(&argv);
    let Some(ov) = override_cmd else {
        return Err(format!(
            "--execute-nc requires --nc-command: the criterion-bound proof command must come from the coordinator, out of band, exactly as --contract-source does. The manifest nominates {line:?} — and the manifest is written by the graded worker, as is the `commands[]` ledger, so neither can authorise the other; fail-closed (#279)"
        ));
    };
    let want = shlex_split(ov, false)
        .map_err(|e| format!("--nc-command is not parseable as a command line ({e})"))?;
    if want.is_empty() {
        return Err("--nc-command is empty after parsing".to_string());
    }
    let want_line = shlex_join(&want);
    if want_line != line {
        return Err(format!(
            "negative_control.command {line:?} is not the command the coordinator supplied out of band ({want_line:?}) — a unit does not get to choose what proves it; fail-closed"
        ));
    }
    if ctx.command_oracle_paths(Some(ov)).is_none() {
        return Err(
            "unsupported proof command: cannot establish executable oracle inputs".to_string(),
        );
    }
    Ok(want)
}

fn production_changes(ctx: &VerifyCtx, base: &str, head: &str) -> Result<Vec<String>, String> {
    if !is_hex40(base) || !is_hex40(head) {
        return Err(
            "base_sha and head_sha must both be pinned 40-hex commits before the class claim can be measured against the change"
                .to_string(),
        );
    }
    let range = format!("{base}..{head}");
    let (code, out_b, _) = ctx.git_bytes(&["diff", "--name-only", "-z", &range], 20);
    if code != 0 {
        return Err(
            "cannot diff base_sha..head_sha, so the class claim cannot be measured".to_string(),
        );
    }
    let out = String::from_utf8_lossy(&out_b);
    let prod: Vec<String> = out
        .split('\0')
        .filter(|p| !p.is_empty())
        .filter(|p| {
            let ext = Path::new(p)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e.to_ascii_lowercase()))
                .unwrap_or_default();
            !PROSE_SUFFIXES.contains(&ext.as_str())
        })
        .map(|s| s.to_string())
        .collect();
    Ok(prod)
}

pub fn changed_paths(
    ctx: &mut VerifyCtx,
    base: &str,
    head: &str,
    nc_command: Option<&str>,
) -> Result<(Vec<String>, Vec<String>), String> {
    if !is_hex40(base) || !is_hex40(head) {
        return Err(
            "the control cannot be bound to the change without pinned 40-hex base_sha and head_sha"
                .to_string(),
        );
    }
    let range = format!("{base}..{head}");
    let (code, out_b, _) =
        ctx.git_bytes(&["diff", "--name-only", "--no-renames", "-z", &range], 20);
    if code != 0 {
        return Err(
            "cannot diff base_sha..head_sha to bind the control to the change; fail-closed"
                .to_string(),
        );
    }
    let out = String::from_utf8_lossy(&out_b);
    let mut prod = Vec::new();
    let mut tests = Vec::new();
    for p in out.split('\0').filter(|s| !s.is_empty()) {
        let is_oracle = ctx.is_oracle_path(p, nc_command, Some(head))?;
        if is_oracle {
            tests.push(p.to_string());
        } else {
            prod.push(p.to_string());
        }
    }
    Ok((prod, tests))
}

pub fn bind_paths_to_change(
    ctx: &mut VerifyCtx,
    paths: &[String],
    m: &EvidenceManifest,
    what: &str,
    nc_command: Option<&str>,
) -> Option<String> {
    let base = m
        .data
        .get("base_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (prod, _tests) = match changed_paths(ctx, base, head, nc_command) {
        Ok(p) => p,
        Err(e) => return Some(e),
    };
    let prod_set: BTreeSet<String> = if let Some(ref scope) = m.oracle_scope {
        scope
            .get("paths")
            .and_then(|v| v.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    } else {
        prod.into_iter().collect()
    };
    for path in paths {
        let norm = pathlib_posix(path);
        match ctx.is_oracle_path(&norm, nc_command, Some(head)) {
            Err(e) => return Some(e),
            Ok(true) => {
                return Some(format!(
                    "{what} names {path:?}, which is a TEST path. Reverting the test that encodes the criterion makes the proof go RED because the oracle is gone, not because the behaviour came back — the control must revert the BEHAVIOUR (#280)"
                ));
            }
            Ok(false) => {}
        }
        if prod_set.contains(&norm) {
            continue;
        }
        let show = if prod_set.is_empty() {
            "'none'".to_string()
        } else {
            let v: Vec<&String> = prod_set.iter().collect();
            format!("{v:?}")
        };
        return Some(format!(
            "{what} names {path:?}, which base_sha..head_sha does not change. A control that reverts a file this unit never touched is a decoy: its RED says nothing about the change being proved. Production paths changed here: {show} (#280)"
        ));
    }
    None
}

fn check_oracle_scope(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    source: Option<&str>,
    digest: Option<&str>,
) -> Vec<String> {
    let (Some(src), Some(dig)) = (source, digest) else {
        return Vec::new();
    };
    let (raw_opt, err) = ctx.read_source(src);
    let Some(raw) = raw_opt else {
        return vec![
            "oracle scope: authoritative contract unreadable or digest mismatch".to_string(),
        ];
    };
    if err.is_some() || sha256_of(&raw) != norm_digest(dig) {
        return vec![
            "oracle scope: authoritative contract unreadable or digest mismatch".to_string(),
        ];
    }
    let text = match std::str::from_utf8(&raw) {
        Ok(t) => t,
        Err(e) => return vec![format!("oracle scope: {e}")],
    };
    let doc = match json_contract(text) {
        Ok(Some(d)) => d,
        Ok(None) => return Vec::new(),
        Err(e) => return vec![format!("oracle scope: {e}")],
    };
    let Some(scope) = doc.get("oracle_scope") else {
        return Vec::new();
    };
    if scope.is_null() {
        return Vec::new();
    }
    let Some(scope_obj) = scope.as_object() else {
        return vec!["oracle scope: kind must be characterization or documentation".to_string()];
    };
    let kind = scope_obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind != "characterization" && kind != "documentation" {
        return vec!["oracle scope: kind must be characterization or documentation".to_string()];
    }
    if scope_obj.get("base_sha") != m.data.get("base_sha")
        || scope_obj.get("head_sha") != m.data.get("head_sha")
    {
        return vec!["oracle scope: authorized commit pair differs from the manifest".to_string()];
    }
    let doc_ids: BTreeSet<String> = doc["criterion_ids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let scope_ids_ok = match scope_obj.get("criterion_ids").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() && arr.iter().all(|x| x.is_string()) => {
            let s: BTreeSet<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|x| x.to_string()))
                .collect();
            s == doc_ids
        }
        _ => false,
    };
    if !scope_ids_ok {
        return vec!["oracle scope: must bind every criterion in this unit's contract".to_string()];
    }
    let Some(paths_obj) = scope_obj.get("paths").and_then(|v| v.as_object()) else {
        return vec!["oracle scope: explicit path/line coordinates required".to_string()];
    };
    if paths_obj.is_empty() {
        return vec!["oracle scope: explicit path/line coordinates required".to_string()];
    }
    let head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base = m
        .data
        .get("base_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    for (p, lines_v) in paths_obj {
        let (_, rerr) = ctx.resolve_evidence(p);
        if rerr.is_some() || ctx.is_oracle_path(p, None, Some(&head)) != Ok(false) {
            return vec![
                "oracle scope: TEST paths and escaping paths cannot be mutated".to_string(),
            ];
        }
        let lines_ok = match lines_v.as_array() {
            Some(arr) if !arr.is_empty() => arr
                .iter()
                .all(|n| !n.is_boolean() && n.as_i64().map(|x| x >= 1).unwrap_or(false)),
            _ => false,
        };
        if !lines_ok {
            return vec!["oracle scope: positive integer line coordinates required".to_string()];
        }
        let spec = format!("{head}:{p}");
        if ctx.git_str(&["cat-file", "-e", &spec], 10).0 != 0 {
            return vec!["oracle scope: target must exist at head_sha".to_string()];
        }
    }
    let (prod, tests) = match changed_paths(ctx, &base, &head, None) {
        Ok(pt) => pt,
        Err(e) => return vec![format!("oracle scope: {e}")],
    };
    for p in prod.iter().chain(tests.iter()) {
        let ext = Path::new(p)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e.to_ascii_lowercase()))
            .unwrap_or_default();
        if !is_test_path(p) && !PROSE_SUFFIXES.contains(&ext.as_str()) {
            return vec![
                "oracle scope: this unit changes production code; default mutation binding required"
                    .to_string(),
            ];
        }
    }
    if kind == "characterization" && tests.is_empty() {
        return vec!["oracle scope: characterization must change a test".to_string()];
    }
    if kind == "documentation" && (!tests.is_empty() || prod.is_empty()) {
        return vec!["oracle scope: documentation must change prose only".to_string()];
    }
    let nc = m
        .data
        .get("negative_control")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let tool = nc.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let art = nc.get("artifact").and_then(|v| v.as_str()).unwrap_or("");
    if tool != "hand" || art.is_empty() {
        return vec!["oracle scope: requires a pinned hand-mutant artifact".to_string()];
    }
    let Ok(content) = read_artifact(ctx, m, art) else {
        return vec!["oracle scope: requires a pinned hand-mutant artifact".to_string()];
    };
    let want_sha = scope_obj
        .get("artifact_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sha256_hex(&content) != want_sha {
        return vec![
            "oracle scope: mutant artifact differs from coordinator authorization".to_string(),
        ];
    }
    let Some(diff) = extract_diff(&String::from_utf8_lossy(&content)) else {
        return vec![
            "oracle scope: every mutant path must match the authorized path set".to_string(),
        ];
    };
    let path_keys: BTreeSet<String> = paths_obj.keys().cloned().collect();
    let targets: BTreeSet<String> = match diff_target_paths(&diff, |p| ctx.resolve_evidence(p)) {
        Ok(t) => t.into_iter().collect(),
        Err(_) => {
            return vec![
                "oracle scope: every mutant path must match the authorized path set".to_string(),
            ];
        }
    };
    if targets != path_keys {
        return vec![
            "oracle scope: every mutant path must match the authorized path set".to_string(),
        ];
    }
    let Ok(touched) = hunk_lines(&diff, '-') else {
        return vec![
            "oracle scope: mutant coordinates exceed coordinator authorization".to_string(),
        ];
    };
    let touched_keys: BTreeSet<String> = touched.keys().cloned().collect();
    if touched_keys != path_keys {
        return vec![
            "oracle scope: mutant coordinates exceed coordinator authorization".to_string(),
        ];
    }
    for (p, lines_v) in paths_obj {
        let allowed: BTreeSet<Coord> = lines_v
            .as_array()
            .expect("arr")
            .iter()
            .filter_map(|x| x.as_i64().map(Coord::whole))
            .collect();
        let got = &touched[p];
        if got.is_empty() || !got.is_subset(&allowed) {
            return vec![
                "oracle scope: mutant coordinates exceed coordinator authorization".to_string(),
            ];
        }
    }
    m.oracle_scope = Some(scope.clone());
    Vec::new()
}

fn check_negative_control(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    is_mut: bool,
    execute: bool,
    nc_command: Option<&str>,
) -> (Vec<String>, bool) {
    if !is_mut {
        return (Vec::new(), false);
    }
    let nc = m
        .data
        .get("negative_control")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut errs = Vec::new();
    let tool = nc.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    if !NC_TOOLS.contains(&tool) {
        let mut sorted = NC_TOOLS.to_vec();
        sorted.sort();
        errs.push(format!(
            "negative_control.tool must be one of {sorted:?}, got {:?}",
            nc.get("tool")
        ));
    }
    let result_text = nc.get("result").and_then(|v| v.as_str()).unwrap_or("");
    if !nc_killed_word_re().is_match(result_text) {
        errs.push(
            "negative_control.result must record the mutant KILLED / the proof going RED"
                .to_string(),
        );
    } else if nc_negated_kill_re().is_match(result_text) {
        errs.push(
            "negative_control.result negates the kill ('not killed' is not KILLED)".to_string(),
        );
    }
    let mutant = nc
        .get("mutant")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    if !tool.is_empty() && tool != "revert" && tool != "hand" && mutant.is_none() {
        errs.push(
            "negative_control.mutant (a pinned mutant id) is required for a mutation tool"
                .to_string(),
        );
    }
    let artifact = nc.get("artifact").and_then(|v| v.as_str()).unwrap_or("");
    if artifact.is_empty() {
        errs.push("negative_control.artifact (an evidence path) is required".to_string());
        return (errs, false);
    }
    let content_bytes = match read_artifact(ctx, m, artifact) {
        Ok(b) => b,
        Err(e) => {
            errs.push(format!(
                "negative_control.artifact unreadable ({artifact}): {e}"
            ));
            return (errs, false);
        }
    };
    let content = String::from_utf8_lossy(&content_bytes).into_owned();
    if !nc_artifact_kill_re().is_match(&content) {
        errs.push("negative_control.artifact does not evidence a killed/RED outcome".to_string());
    }
    if nc_zero_kill_re().is_match(&content) {
        errs.push(
            "negative_control.artifact indicates no mutant was killed (0 killed / 0% killed)"
                .to_string(),
        );
    }
    let mutant_surv_re = Regex::new(r"(?i)\bmutant\s+survived\b").expect("re");
    let survived = has_survived_nonzero(&content, &mutant_surv_re)
        || mutant.is_some_and(|mid| {
            let pat = format!(
                r"(?i)\b{}\b[\s:=<>-]*(?:has\s+|was\s+)?survived\b",
                regex::escape(mid)
            );
            Regex::new(&pat)
                .map(|re| has_survived_nonzero(&content, &re))
                .unwrap_or(false)
        });
    if survived {
        errs.push(
            "negative_control.artifact reports the pinned mutant SURVIVED / was not killed"
                .to_string(),
        );
    }
    if let Some(mid) = mutant {
        if !content.contains(mid) {
            errs.push("negative_control.artifact does not reference the pinned mutant".to_string());
        }
    }
    let base = m
        .data
        .get("base_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pinned = is_hex40(&base) && is_hex40(&head);

    if tool == "hand" {
        let quoted_hand = extract_diff(&content);
        let (hand_targets, hand_parse_err) = match &quoted_hand {
            Some(qh) => iter_diff_target_paths(qh, |p| ctx.resolve_evidence(p)),
            None => (BTreeSet::new(), None),
        };
        if quoted_hand.is_none() || (hand_targets.is_empty() && hand_parse_err.is_none()) {
            errs.push(
                "negative_control.artifact for tool 'hand' must quote the hand-written diff with unified file headers and parseable target paths".to_string(),
            );
        } else if let Some(hpe) = hand_parse_err {
            if !pinned {
                errs.push(format!(
                    "negative_control.artifact for tool 'hand' quotes an unparseable hand-written diff: {hpe}"
                ));
            }
        }
    }

    if tool == "revert" {
        let (declared, perr) = nc_paths(&nc, |p| ctx.resolve_evidence(p));
        if let Some(e) = perr {
            errs.push(e);
        } else if let Some(dec) = declared {
            if let Some(be) =
                bind_paths_to_change(ctx, &dec, m, "negative_control.paths", nc_command)
            {
                errs.push(be);
            }
        } else if pinned {
            match changed_paths(ctx, &base, &head, nc_command) {
                Err(e) => errs.push(e),
                Ok((_prod, mut oracle)) => {
                    if !oracle.is_empty() {
                        oracle.sort();
                        errs.push(format!(
                            "range revert changes test paths or runner oracle inputs {oracle:?}; name only production negative_control.paths"
                        ));
                    }
                }
            }
        }
    } else if EXECUTABLE_NC_TOOLS.contains(&tool) {
        if let Some(quoted) = extract_diff(&content) {
            if pinned {
                let (targets_set, parse_err) =
                    iter_diff_target_paths(&quoted, |p| ctx.resolve_evidence(p));
                let targets: Vec<String> = targets_set.into_iter().collect();
                if let Some(be) =
                    bind_paths_to_change(ctx, &targets, m, "the hand mutant's diff", nc_command)
                {
                    errs.push(be);
                }
                let hunk_err = parse_err.or_else(|| {
                    bind_hunks_to_change(
                        &quoted,
                        &m.data,
                        m.oracle_scope.as_ref(),
                        |p| ctx.resolve_evidence(p),
                        |a| ctx.git_str(a, 10),
                    )
                });
                if let Some(he) = hunk_err {
                    errs.push(he);
                }
            }
        }
    }

    let mut executed_ok = false;
    if execute && errs.is_empty() {
        let (ok, msgs) = execute_negative_control(ctx, m, nc_command);
        executed_ok = ok;
        errs.extend(msgs);
    }
    (errs, executed_ok)
}

fn check_commands(
    ctx: &VerifyCtx,
    m: &Value,
    is_mut: bool,
    nc_command: Option<&str>,
) -> Vec<String> {
    if !is_mut {
        return Vec::new();
    }
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    if head.is_empty() {
        return Vec::new();
    }
    let Some(want) = ctx.tree_of(head) else {
        return vec![
            "commands ledger: cannot resolve the tree of head_sha (not a real commit here, or not inside a git repo) — the recorded run cannot be bound to content; fail-closed".to_string(),
        ];
    };
    let records: Vec<&Map<String, Value>> = m
        .get("commands")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|c| c.as_object()).collect())
        .unwrap_or_default();
    if records.is_empty() {
        return vec![
            "commands ledger: no recorded command (mutation unit). Wrap the criterion-bound run in `runtime/scripts/evidence-run.py --label <L> --manifest <m.json> -- <cmd>` so the manifest carries an exit code bound to a content fingerprint; fail-closed".to_string(),
        ];
    }
    for rec in &records {
        let line = match rec.get("cmd").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return vec![
                    "commands ledger: a commands[] record omits a valid command string (`cmd`) — the record describes nothing, so it binds nothing; fail-closed (#768)".to_string(),
                ];
            }
        };
        let digest = match rec.get("cmd_sha256").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return vec![format!(
                    "commands ledger: record for {line:?} omits a valid cmd_sha256 string — a record without its command digest binds nothing; fail-closed (#768)"
                )];
            }
        };
        let actual = sha256_hex(line.as_bytes());
        if digest != actual {
            return vec![format!(
                "commands ledger: record for {line:?} carries cmd_sha256 {digest} but the command line hashes to {actual} — the record does not describe its own command, so it binds nothing; fail-closed"
            )];
        }
    }
    let is_exit_zero = |r: &&Map<String, Value>| -> bool {
        match r.get("exit") {
            Some(Value::Number(n)) => n.as_i64() == Some(0),
            _ => false,
        }
    };
    let fresh: Vec<&&Map<String, Value>> = records
        .iter()
        .filter(|r| {
            is_exit_zero(r) && r.get("wtree").and_then(|v| v.as_str()) == Some(want.as_str())
        })
        .collect();
    if fresh.is_empty() {
        if let Some(why) = records.iter().find_map(|c| {
            if is_exit_zero(c) && c.get("wtree").map(|v| v.is_null()).unwrap_or(true) {
                c.get("wtree_unverifiable").and_then(|v| v.as_str())
            } else {
                None
            }
        }) {
            let short: String = why.chars().take(300).collect();
            return vec![format!(
                "commands ledger: the exit-0 run carries no fingerprint for head_sha's tree {want} because its working tree was UNVERIFIABLE, not stale: {short:?} — the coordinator's clean-env re-run at head_sha is the authority for this unit; fail-closed (#629)"
            )];
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for c in &records {
            if is_exit_zero(c) {
                let s = match c.get("wtree") {
                    Some(Value::String(st)) => st.clone(),
                    Some(Value::Null) | None => "None".to_string(),
                    Some(other) => other.to_string(),
                };
                seen.insert(s);
            }
        }
        let seen_s = if seen.is_empty() {
            "'no wtree at all'".to_string()
        } else {
            let v: Vec<&String> = seen.iter().collect();
            format!("{v:?}")
        };
        return vec![format!(
            "commands ledger: no recorded command with exit 0 whose wtree is head_sha's tree {want} (exit-0 records carry {seen_s}) — the recorded run was made on other content, so it is STALE evidence for this head; fail-closed"
        )];
    }
    if let Some(nc_cmd) = nc_command {
        let want_cmd = shlex_split(nc_cmd, false)
            .ok()
            .filter(|a| !a.is_empty())
            .map(|a| shlex_join(&a));
        let Some(wc) = want_cmd else {
            return vec![format!(
                "commands ledger: --nc-command {nc_cmd:?} is empty or unparseable — the coordinator named no usable proof command; fail-closed (#352)"
            )];
        };
        let matched = fresh.iter().any(|rec| {
            rec.get("cmd")
                .and_then(|v| v.as_str())
                .and_then(|l| shlex_split(l, false).ok())
                .map(|a| shlex_join(&a) == wc)
                .unwrap_or(false)
        });
        if !matched {
            let mut ran: BTreeSet<String> = BTreeSet::new();
            for rec in &fresh {
                ran.insert(
                    rec.get("cmd")
                        .and_then(|v| v.as_str())
                        .unwrap_or("None")
                        .to_string(),
                );
            }
            let ran_v: Vec<&String> = ran.iter().collect();
            return vec![format!(
                "commands ledger: fresh exit-0 record(s) exist, but none is the coordinator-named proof command {wc:?} (fresh records ran: {ran_v:?}) — the ledger proves SOMETHING ran green on this content, not the proof the coordinator named; fail-closed (#352)"
            )];
        }
    }
    let short_tree = &want[..12.min(want.len())];
    vec![format!(
        "NOTE: commands ledger FRESH — {} exit-0 record(s) bound to head_sha's tree {short_tree}. This is the worker's own runner, so the coordinator's clean-env re-run at head_sha still stands as the stronger authority (evidence-manifest.md §2)",
        fresh.len()
    )]
}

fn gitleaks_scan(ctx: &VerifyCtx, scan_path: &Path) -> Option<bool> {
    let gl = ctx.gitleaks_bin.as_deref()?;
    if ctx.gitleaks_custody.as_deref() != Some("system") && ctx.lane.is_some() {
        return None;
    }
    let args = vec![
        OsString::from("detect"),
        OsString::from("--no-git"),
        OsString::from("--no-banner"),
        OsString::from("--redact"),
        OsString::from("--source"),
        scan_path.as_os_str().to_os_string(),
    ];
    let (code, _, _) = run_proc_bytes(gl, &args, scan_path.parent(), &ctx.git_env(), None, 120);
    match code {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn check_redaction(ctx: &mut VerifyCtx, m: &mut EvidenceManifest) -> Vec<String> {
    let mut errs = Vec::new();
    let mut targets: Vec<(String, Vec<u8>)> = vec![
        (
            "manifest".to_string(),
            serde_json::to_string(&m.data)
                .unwrap_or_default()
                .into_bytes(),
        ),
        ("manifest bytes".to_string(), m.raw.clone()),
    ];
    let mut named: Vec<String> = Vec::new();
    let mut seen_named: HashSet<String> = HashSet::new();
    let mut push_name = |p: &str| {
        if !p.is_empty() && seen_named.insert(p.to_string()) {
            named.push(p.to_string());
        }
    };
    if let Some(p) = m
        .data
        .get("negative_control")
        .and_then(|v| v.get("artifact"))
        .and_then(|v| v.as_str())
    {
        push_name(p);
    }
    if let Some(p) = m
        .data
        .get("review")
        .and_then(|v| v.get("artifact"))
        .and_then(|v| v.as_str())
    {
        push_name(p);
    }
    if let Some(arr) = m.data.get("artifacts").and_then(|v| v.as_array()) {
        for entry in arr {
            let p = match entry {
                Value::Object(o) => o.get("path").and_then(|v| v.as_str()),
                Value::String(s) => Some(s.as_str()),
                _ => None,
            };
            if let Some(s) = p {
                push_name(s);
            }
        }
    }
    if let Some(arr) = m.data.get("commands").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(s) = entry.get("artifact").and_then(|v| v.as_str()) {
                push_name(s);
            }
        }
    }
    for path in named {
        match read_artifact(ctx, m, &path) {
            Ok(raw) => targets.push((format!("artifact {path}"), raw)),
            Err(e) => errs.push(format!("redaction: artifact {path} unreadable: {e}")),
        }
    }
    let tmp = tempfile::Builder::new().prefix("orca-redaction-").tempdir();
    let scan_path = tmp.as_ref().ok().map(|t| t.path().join("evidence.txt"));
    for (label, raw) in targets {
        let text = String::from_utf8_lossy(&raw);
        let mut kinds: BTreeSet<&str> = redaction_patterns()
            .iter()
            .filter(|(_, rx)| rx.is_match(&text))
            .map(|(name, _)| *name)
            .collect();
        if let Some(ref sp) = scan_path {
            if fs::write(sp, &raw).is_ok()
                && gitleaks_scan(ctx, sp) == Some(true)
                && kinds.is_empty()
            {
                kinds.insert("gitleaks-rule");
            }
        }
        if !kinds.is_empty() {
            let kv: Vec<&str> = kinds.into_iter().collect();
            errs.push(format!(
                "redaction: credential shape(s) {kv:?} found in {label} — evidence is SHA-pinned and permanent; rotate the credential and re-emit the unit"
            ));
        }
    }
    errs
}

fn check_ancestry(ctx: &VerifyCtx, m: &Value, base: Option<&str>) -> Vec<String> {
    let Some(b) = base.filter(|s| !s.is_empty()) else {
        return vec![
            "NOTE: --base not given — ancestry check skipped (pre-merge/offline)".to_string(),
        ];
    };
    let shown = format!("origin/{b}");
    let full_ref = format!("refs/remotes/origin/{b}");
    let (tip_opt, _, why_opt) = ctx.anchor_commit(&full_ref);
    let Some(tip) = tip_opt else {
        let why = format!("{full_ref} {}", why_opt.unwrap_or_default());
        if let Some(ref lane) = ctx.lane {
            return vec![format!(
                "ancestry: {shown} not found — a lane claiming soundness ({lane}) named --base and cannot skip the ancestry proof it asked for; fail-closed ({why})"
            )];
        }
        return vec![format!(
            "NOTE: {shown} not found — ancestry check skipped ({why})"
        )];
    };
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    if ctx
        .git_str(&["merge-base", "--is-ancestor", head, &tip], 10)
        .0
        != 0
    {
        return vec![format!(
            "head_sha is not an ancestor of {shown} (not merged / wrong base)"
        )];
    }
    Vec::new()
}

fn check_base_binding(
    ctx: &VerifyCtx,
    m: &Value,
    base: Option<&str>,
    execute_nc: bool,
) -> Vec<String> {
    let base_sha = m.get("base_sha").and_then(|v| v.as_str()).unwrap_or("");
    if !is_hex40(base_sha) {
        return Vec::new();
    }
    let Some(b) = base.filter(|s| !s.is_empty()) else {
        if execute_nc {
            if let Some(ref lane) = ctx.lane {
                return vec![format!(
                    "base binding: a lane claiming soundness ({lane}) executes the control without --base, so base_sha — the content the control restores — is bound to no branch the coordinator owns; name --base (fail-closed)"
                )];
            }
            return vec![
                "NOTE: --base not given — base_sha, the content the executed control restores, is bound to no branch (worker-chosen on this lane)".to_string(),
            ];
        }
        return Vec::new();
    };
    let (tip_opt, _, _) = ctx.anchor_commit(&format!("refs/remotes/origin/{b}"));
    let Some(tip) = tip_opt else {
        return Vec::new();
    };
    if ctx
        .git_str(&["merge-base", "--is-ancestor", base_sha, &tip], 10)
        .0
        != 0
    {
        let short = &base_sha[..12.min(base_sha.len())];
        return vec![format!(
            "base_sha {short} is not an ancestor of origin/{b} — the control would restore content the integration branch never held, so the worker chose its own base (2026-10-26 review)"
        )];
    }
    Vec::new()
}

fn check_symbol_on_base(ctx: &VerifyCtx, symbol: Option<&str>, base: Option<&str>) -> Vec<String> {
    let (Some(sym), Some(b)) = (
        symbol.filter(|s| !s.is_empty()),
        base.filter(|s| !s.is_empty()),
    ) else {
        return Vec::new();
    };
    let full_ref = format!("refs/remotes/origin/{b}");
    let (tip_opt, _, why_opt) = ctx.anchor_commit(&full_ref);
    let Some(tip) = tip_opt else {
        return vec![format!(
            "symbol '{sym}' not found on origin/{b}: the base does not resolve by its exact name ({full_ref} {})",
            why_opt.unwrap_or_default()
        )];
    };
    let (code, out) = ctx.git_str(&["grep", "-l", "-e", sym, &tip], 20);
    if code != 0 || out.trim().is_empty() {
        return vec![format!(
            "symbol '{sym}' not found on origin/{b} (change may not be on base)"
        )];
    }
    Vec::new()
}

fn check_intent(m: &Value, is_mut: bool) -> Vec<String> {
    if !is_mut {
        return Vec::new();
    }
    let intent = m.get("intent").and_then(|v| v.as_object());
    let missing: Vec<&str> = ["goal", "ruled_out", "why"]
        .into_iter()
        .filter(|k| {
            !intent
                .and_then(|o| o.get(*k))
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        })
        .collect();
    if missing.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "intent packet incomplete — non-empty {} required (mutation unit)",
            py_repr_list(&missing)
        )]
    }
}

fn check_lighting(
    m: &Value,
    is_mut: bool,
    dispatch_lighting: Option<&str>,
    dispatch_lane: Option<&str>,
) -> Vec<String> {
    if !is_mut {
        return Vec::new();
    }
    let lighting_val = m.get("lighting");
    let lighting = match lighting_val {
        None => "lit",
        Some(Value::String(s)) if LIGHTING_VALUES.contains(&s.as_str()) => s.as_str(),
        Some(other) => {
            return vec![format!(
                "lighting must be one of ['dark-eligible', 'lit'], got {}",
                py_repr_val(Some(other))
            )];
        }
    };
    if let Some(dl) = dispatch_lighting {
        if lighting != dl {
            return vec![format!(
                "lighting swap: manifest says {} but dispatch classed the unit {} (the dispatch value is authoritative)",
                py_repr_str(lighting),
                py_repr_str(dl)
            )];
        }
    }
    let lane_val = m.get("lane");
    let lane_str = match lane_val {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if matches!(s.as_str(), "A" | "B" | "0") => Some(s.as_str()),
        Some(other) => {
            return vec![format!(
                "lane must be one of ['A', 'B', '0'], got {}",
                py_repr_val(Some(other))
            )];
        }
    };
    let Some(dlane) = dispatch_lane else {
        return Vec::new();
    };
    if let Some(ls) = lane_str {
        if ls != dlane {
            return vec![format!(
                "lane swap: manifest says {} but dispatch classed the unit {} (the dispatch value is authoritative)",
                py_repr_str(ls),
                py_repr_str(dlane)
            )];
        }
    }
    if dlane == "0" {
        return vec![
            "Lane 0 (refuse-and-surface) unit is being verified as a landed mutation — Lane 0 work is recorded and surfaced, never built (gate-classification.md)".to_string(),
        ];
    }
    let effective = dispatch_lighting.unwrap_or(lighting);
    if effective == "dark-eligible" && dlane != "A" {
        return vec![format!(
            "dark-eligible unit on Lane {dlane}: dark-eligibility requires Lane A (gate-classification.md)"
        )];
    }
    Vec::new()
}

fn check_reviewer_mode(m: &Value, is_mut: bool) -> Vec<String> {
    if !is_mut {
        return Vec::new();
    }
    match m.get("reviewer_mode") {
        Some(Value::String(s)) if REVIEWER_MODES.contains(&s.as_str()) => Vec::new(),
        other => vec![format!(
            "reviewer_mode must be one of ['cross-vendor', 'instructed-isolation', 'same-vendor-fresh'], got {}",
            py_repr_val(other)
        )],
    }
}

fn check_provenance(m: &Value) -> Vec<String> {
    let Some(prov) = m.get("provenance").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let std_s = prov
        .get("standard")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .unwrap_or("");
    if std_s.is_empty() || std_s.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let missing: Vec<&str> = ["spec_version", "model", "reviewer", "retention"]
        .into_iter()
        .filter(|k| {
            !prov
                .get(*k)
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        })
        .collect();
    if missing.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "provenance claims standard {} but is missing audit fields {} (EU AI Act Art-12/50 record incomplete)",
            py_repr_str(std_s),
            py_repr_list(&missing)
        )]
    }
}

fn check_retention_receipt(
    ctx: &VerifyCtx,
    m: &EvidenceManifest,
    pubkey_ref: Option<&str>,
) -> Vec<String> {
    let prov = m.data.get("provenance").and_then(|v| v.as_object());
    let claim_val = prov.and_then(|o| o.get("retention_receipt"));
    let claim_present = claim_val.is_some_and(|v| !v.is_null());
    if !claim_present && pubkey_ref.filter(|s| !s.is_empty()).is_none() {
        return Vec::new();
    }
    if claim_present && claim_val.and_then(|v| v.as_str()) != Some(RECEIPT_SCHEMA) {
        return vec![format!(
            "provenance.retention_receipt claims {:?}; this verifier binds {RECEIPT_SCHEMA:?} only — fail-closed (#608)",
            claim_val
        )];
    }
    let Some(pk_ref) = pubkey_ref.filter(|s| !s.is_empty()) else {
        let cs = claim_val.and_then(|v| v.as_str()).unwrap_or("");
        return vec![format!(
            "provenance claims the {cs} retention binding, but no trust material was supplied (--retention-pubkey) — a key inside a receipt never establishes trust, so there is nothing to verify it against; fail-closed (#608)"
        )];
    };
    let (key_where, key_read, _pinned, refused) =
        ctx.key_source(pk_ref, "--retention-pubkey", true);
    if let Some(r) = refused {
        return vec![r];
    }
    let (pub_opt, err) = ctx.read_source(&key_read);
    let pub_bytes: [u8; 32] = match pub_opt {
        Some(raw) => {
            let s = String::from_utf8_lossy(&raw).trim().to_string();
            match hex::decode(&s) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    return vec![format!(
                        "retention trust key {pk_ref} is unreadable or not a 32-byte Ed25519 public key (wrong length) — fail-closed (#608)"
                    )];
                }
            }
        }
        None => {
            return vec![format!(
                "retention trust key {pk_ref} is unreadable or not a 32-byte Ed25519 public key ({}) — fail-closed (#608)",
                err.unwrap_or_else(|| "wrong length".to_string())
            )];
        }
    };

    let read_rel = |what: &str, path_opt: Option<&str>| -> Result<Vec<u8>, String> {
        let p = match path_opt {
            Some(s) if !s.trim().is_empty() => s,
            _ => return Err(format!("no {what} path is named")),
        };
        if p.contains('@') {
            return Err(format!(
                "{what} {p:?} must be a repo-relative path, not a path@ref (#267)"
            ));
        }
        let (full_opt, why) = ctx.resolve_evidence(p);
        if let Some(w) = why {
            return Err(format!("{what} {p:?} refused: {w}"));
        }
        let full = full_opt.expect("full");
        if !full.exists() {
            return Err(format!("{what} {p:?} is missing — no file at that path"));
        }
        fs::read(&full).map_err(|e| format!("{what} {p:?} is unreadable ({e})"))
    };

    let receipt = prov
        .and_then(|o| o.get("retention"))
        .and_then(|v| v.as_str());
    let raw = match read_rel("retention receipt", receipt) {
        Ok(b) => b,
        Err(e) => {
            return vec![format!(
                "{e}; the retention binding is claimed, so it fails closed (#608)"
            )];
        }
    };
    let receipt_s = receipt.unwrap_or("");
    let env_map = match parse_receipt(&raw) {
        Ok(e) => e,
        Err(why) => {
            return vec![format!(
                "retention receipt {receipt_s} is unreadable as a v1 receipt ({RECEIPT_SCHEMA}): {why} (#608)"
            )];
        }
    };
    let record = env_map["record"].as_object().expect("record");
    // Verify receipt signature, signer, unit, source_revision
    let want_signer = signer_id(&pub_bytes);
    let rec_signer = record.get("signer").and_then(|v| v.as_str()).unwrap_or("");
    if rec_signer != want_signer {
        return vec![format!(
            "retention receipt {receipt_s} refused: signer {rec_signer:?} does not match the supplied public key ({want_signer}) (#608)"
        )];
    }
    let sig_b64 = env_map
        .get("sig_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sig = match decode_strict(sig_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return vec![format!(
                "retention receipt {receipt_s} refused: sig_b64 is malformed (#608)"
            )];
        }
    };
    let msg = canonical_record(record, RECEIPT_FIELDS);
    if !verify_bytes(&sig, &msg, &pub_bytes) {
        return vec![format!(
            "retention receipt {receipt_s} refused: receipt signature INVALID for the supplied public key (#608)"
        )];
    }
    let m_unit = m.data.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    let r_unit = record.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    if m_unit.is_empty() || r_unit != m_unit {
        return vec![format!(
            "retention receipt {receipt_s} refused: receipt unit {r_unit:?} does not match manifest unit {m_unit:?} (#608)"
        )];
    }
    let m_head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let r_rev = record
        .get("source_revision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if m_head.is_empty() || r_rev != m_head {
        return vec![format!(
            "retention receipt {receipt_s} refused: receipt source_revision {r_rev:?} does not match manifest head_sha {m_head:?} (#608)"
        )];
    }

    let inv_rel = record
        .get("inventory")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let doc_bytes = match read_rel("inventory document", Some(inv_rel)) {
        Ok(b) => b,
        Err(e) => {
            return vec![format!(
                "retention receipt {receipt_s}: {e}; fail-closed (#608)"
            )];
        }
    };
    let doc_text = match std::str::from_utf8(&doc_bytes) {
        Ok(t) => t,
        Err(e) => {
            return vec![format!(
                "retention receipt {receipt_s}: {inv_rel} is not UTF-8 text ({e}); fail-closed (#608)"
            )];
        }
    };
    let lines: Vec<String> = doc_text.lines().map(|l| l.to_string()).collect();
    let blocks = match crate::inventory::find_blocks(&lines) {
        Ok(b) => b,
        Err(why) => {
            return vec![format!(
                "retention receipt {receipt_s} refused: {why} (#608)"
            )];
        }
    };
    let mut entries = Vec::new();
    for (start, end) in blocks {
        match crate::inventory::parse_entries(&lines, start, end) {
            Ok(part) => entries.extend(part),
            Err(why) => {
                return vec![format!(
                    "retention receipt {receipt_s} refused: {why} (#608)"
                )];
            }
        }
    }
    let found_sig = match find_signature(&lines) {
        Ok(Some((_, env))) => env,
        Ok(None) => {
            return vec![format!(
                "retention receipt {receipt_s} refused: inventory document {inv_rel} carries no inventory-signature (#608)"
            )];
        }
        Err(why) => {
            return vec![format!(
                "retention receipt {receipt_s} refused: {why} (#608)"
            )];
        }
    };
    let digest = match verify_signature(&found_sig, &entries, &pub_bytes) {
        Ok(d) => d,
        Err(why) => {
            return vec![format!(
                "retention receipt {receipt_s} refused: {why} (#608)"
            )];
        }
    };
    let rec_inv_sha = record
        .get("inventory_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if digest != rec_inv_sha {
        return vec![format!(
            "retention receipt {receipt_s} refused: receipt inventory_sha256 {rec_inv_sha} does not match signed inventory digest {digest} (#608)"
        )];
    }

    let mine = sha256_hex(&m.raw);
    let pinned_at: Vec<String> = entries
        .iter()
        .filter(|e| e.recorded_hash == mine)
        .map(|e| e.path.clone())
        .collect();
    if pinned_at.is_empty() {
        return vec![format!(
            "retention receipt {receipt_s} refused: {inv_rel} does not pin this manifest's exact bytes (sha256 {mine}) — the receipt covers some other record of this unit (#608)"
        )];
    }
    let doc_path = ctx.resolve_evidence(inv_rel).0;
    let top = ctx.evidence_toplevel();
    let here_canon = m.path.as_deref().and_then(|h| fs::canonicalize(h).ok());
    let named: Vec<String> = pinned_at
        .iter()
        .filter(|entry| {
            let Some(ref dp) = doc_path else {
                return false;
            };
            let Some(found) = resolve_entry(entry, dp, top.as_deref()) else {
                return false;
            };
            match (fs::canonicalize(found), &here_canon) {
                (Ok(a), Some(b)) => &a == b,
                _ => false,
            }
        })
        .cloned()
        .collect();
    if named.is_empty() {
        return vec![format!(
            "retention receipt {receipt_s} refused: {inv_rel} pins this manifest's bytes only as {pinned_at:?}, not under this manifest's own path {:?} — a byte-copy stands in for the record the receipt claims to cover (W3-04, #608)",
            m.path
        )];
    }
    let rev_short = &r_rev[..12.min(r_rev.len())];
    let dig_short = &digest[..12.min(digest.len())];
    let uuid = record
        .get("entry_uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let uuid_short = &uuid[..16.min(uuid.len())];
    let log_idx = record
        .get("log_index")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    vec![format!(
        "NOTE: retention receipt {receipt_s} verified OFFLINE against the supplied key — {key_where} (W3-03) — (#608): signed by {rec_signer} over the {RECEIPT_SCHEMA} payload, binding unit {r_unit:?} at source revision {rev_short} to inventory digest {dig_short}… of {inv_rel}, whose entries carry the same key's signature and pin this manifest's bytes as its entry {} (W3-04). NOT verified: that log entry {uuid_short}… (index {log_idx}) exists or is included in any transparency log (a live lookup run out of band), any retention period or storage, that the listed files still hash to the inventory (inventory.py check / run_report.py), or any legal or regulatory determination",
        named[0]
    )]
}

struct DispatchProvOpts<'a> {
    contract_digest: Option<&'a str>,
    unit_class: Option<&'a str>,
    lighting: Option<&'a str>,
    record_ref: Option<&'a str>,
    pubkey_ref: Option<&'a str>,
    no_gh: bool,
    lane: Option<&'a str>,
    execute_nc: bool,
    allow_static_nc: bool,
}

fn check_dispatch_provenance(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    opts: &DispatchProvOpts<'_>,
) -> Vec<String> {
    let DispatchProvOpts {
        contract_digest,
        unit_class,
        lighting,
        record_ref,
        pubkey_ref,
        no_gh,
        lane,
        execute_nc,
        allow_static_nc,
    } = *opts;
    let rec_set = record_ref.filter(|s| !s.is_empty());
    let pub_set = pubkey_ref.filter(|s| !s.is_empty());
    if rec_set.is_none() && pub_set.is_none() {
        return Vec::new();
    }
    if rec_set.is_some() != pub_set.is_some() {
        let missing = if pub_set.is_some() {
            "--dispatch-record"
        } else {
            "--dispatch-pubkey"
        };
        return vec![format!(
            "dispatch provenance half-configured (missing {missing}) — cannot verify; fail-closed (#135)"
        )];
    }
    let rec_s = rec_set.expect("rec");
    let pub_s = pub_set.expect("pub");
    let (key_where, key_read, key_pinned, refused) =
        ctx.key_source(pub_s, "--dispatch-pubkey", true);
    if let Some(r) = refused {
        return vec![r];
    }
    let (record_where, _, _, _) = ctx.key_source(rec_s, "--dispatch-record", true);
    let (rec_opt, rec_err) = ctx.read_source(rec_s);
    if let Some(e) = rec_err {
        return vec![format!("dispatch record unreadable ({rec_s}): {e}")];
    }
    let (pub_opt, pub_err) = ctx.read_source(&key_read);
    if let Some(e) = pub_err {
        return vec![format!("dispatch pubkey unreadable ({pub_s}): {e}")];
    }
    let rec_bytes = rec_opt.expect("rec");
    let pub_bytes_raw = pub_opt.expect("pub");
    let env_val: Value = match serde_json::from_slice(&rec_bytes) {
        Ok(v) => v,
        Err(e) => return vec![format!("dispatch record / pubkey malformed ({e})")],
    };
    let Some(env_obj) = env_val.as_object() else {
        return vec!["dispatch record malformed (envelope must be a JSON object)".to_string()];
    };
    let Some(record_val) = env_obj.get("record") else {
        return vec!["dispatch record / pubkey malformed ('record')".to_string()];
    };
    let Some(record) = record_val.as_object() else {
        return vec!["dispatch record malformed ('record' must be a JSON object)".to_string()];
    };
    let Some(sig_b64) = env_obj.get("sig_b64").and_then(|v| v.as_str()) else {
        return vec!["dispatch record / pubkey malformed ('sig_b64')".to_string()];
    };
    let sig = match decode_strict(sig_b64) {
        Ok(b) => b,
        Err(e) => return vec![format!("dispatch record / pubkey malformed ({e})")],
    };
    let pub_hex = String::from_utf8_lossy(&pub_bytes_raw).trim().to_string();
    let pub_key = match hex::decode(&pub_hex) {
        Ok(b) => b,
        Err(e) => return vec![format!("dispatch record / pubkey malformed ({e})")],
    };
    let canon = canonical_record(record, RECORD_FIELDS);
    if !verify_bytes(&sig, &canon, &pub_key) {
        return vec![
            "dispatch record signature INVALID for the supplied pubkey — not signed by that key (forged or wrong key); fail-closed (#135)".to_string(),
        ];
    }
    let signed_id = record.get("manifest_id").and_then(|v| v.as_str());
    let manifest_id = m.data.get("unit").and_then(|v| v.as_str());
    if signed_id.filter(|s| !s.is_empty()).is_none()
        || manifest_id.filter(|s| !s.is_empty()).is_none()
        || signed_id != manifest_id
    {
        return vec![format!(
            "dispatch record identity {} does not bind this manifest {} — a record must name the unit it authorizes, else another unit's record replays (#135)",
            py_repr_val(record.get("manifest_id")),
            py_repr_val(m.data.get("unit"))
        )];
    }
    for (field, used) in [
        ("contract_digest", contract_digest),
        ("unit_class", unit_class),
        ("lighting", lighting),
        ("lane", lane),
    ] {
        let Some(u) = used else {
            continue;
        };
        let Some(signed) = record.get(field).filter(|v| !v.is_null()) else {
            return vec![format!(
                "dispatch record did not sign {field} but the run uses it — unbound value, fail-closed (the coordinator must sign every field the gate enforces) (#135)"
            )];
        };
        if signed.as_str() != Some(u) {
            return vec![format!(
                "dispatch substitution: the run used {field}={} but the coordinator signed {} — the value was tampered (#135)",
                py_repr_str(u),
                py_repr_val(Some(signed))
            )];
        }
    }
    for (field, used, waiver) in [
        ("no_gh", no_gh, true),
        ("execute_nc", execute_nc, false),
        ("allow_static_nc", allow_static_nc, true),
    ] {
        let Some(signed) = record.get(field).filter(|v| !v.is_null()) else {
            if used && waiver {
                return vec![format!(
                    "dispatch record did not sign {field} but the run uses it — the review waiver is unbound, fail-closed (sign it with dispatch-sign.py --no-gh) (review P2)"
                )];
            }
            continue;
        };
        if signed.as_bool() != Some(used) {
            return vec![format!(
                "dispatch substitution: the run used {field}={} but the coordinator signed {} — the lane flag was tampered (review P2)",
                if used { "True" } else { "False" },
                py_repr_val(Some(signed))
            )];
        }
    }

    // Signed negative-control inputs (#311)
    let nc = m
        .data
        .get("negative_control")
        .cloned()
        .unwrap_or(Value::Null);
    let claimed_paths: Value = match nc.get("paths") {
        Some(Value::Array(arr)) => {
            let mut s: Vec<String> = arr
                .iter()
                .map(|x| match x {
                    Value::String(st) => st.clone(),
                    other => other.to_string(),
                })
                .collect();
            s.sort();
            Value::Array(s.into_iter().map(Value::String).collect())
        }
        Some(other) => other.clone(),
        None => Value::Null,
    };
    let claimed_cmd = nc.get("command").cloned().unwrap_or(Value::Null);
    let claimed_art_sha = match nc.get("artifact").and_then(|v| v.as_str()) {
        Some(art) if !art.is_empty() => match read_artifact(ctx, m, art) {
            Ok(raw) => Value::String(sha256_hex(&raw)),
            Err(_) => Value::Null,
        },
        _ => Value::Null,
    };
    for (field, claimed) in [
        ("nc_paths", claimed_paths),
        ("nc_command", claimed_cmd),
        ("nc_artifact_sha256", claimed_art_sha),
    ] {
        let Some(raw_signed) = record.get(field).filter(|v| !v.is_null()) else {
            continue;
        };
        let signed = if field == "nc_paths" {
            if let Some(arr) = raw_signed.as_array() {
                let mut s: Vec<String> = arr
                    .iter()
                    .map(|x| match x {
                        Value::String(st) => st.clone(),
                        other => other.to_string(),
                    })
                    .collect();
                s.sort();
                Value::Array(s.into_iter().map(Value::String).collect())
            } else {
                raw_signed.clone()
            }
        } else {
            raw_signed.clone()
        };
        if claimed.is_null() {
            return vec![format!(
                "dispatch record signs {field} but the manifest carries no value for it — the coordinator chose the control's inputs and this unit did not use them; fail-closed (#311)"
            )];
        }
        if signed != claimed {
            return vec![format!(
                "dispatch substitution: the manifest's {field}={claimed} but the coordinator signed {signed} — the worker chose its own oracle (#311)"
            )];
        }
    }
    if let Some(signed_base) = record.get("base_sha").filter(|v| !v.is_null()) {
        let m_base = m.data.get("base_sha").unwrap_or(&Value::Null);
        if signed_base != m_base {
            return vec![format!(
                "dispatch substitution: the manifest's base_sha={m_base} but the coordinator signed {signed_base} — the control's pre-fix content was swapped"
            )];
        }
    }
    let advisory = if key_pinned {
        ""
    } else {
        " — ADVISORY: a key the graded worker can swap opens no enforcement lane; the signature is checked, with no soundness claim (PR #719 review)"
    };
    vec![format!(
        "NOTE: dispatch record signature verified against the supplied key (#135) — a soundness boundary only if that key is trusted (off-worker: CI/MCP/SDK or an auditor); key: {key_where}; record: {record_where} (W3-03){advisory}"
    )]
}

fn check_class_downgrade(
    ctx: &VerifyCtx,
    m: &Value,
    unit_class: Option<&str>,
    record_ref: Option<&str>,
    pubkey_ref: Option<&str>,
) -> Vec<String> {
    if is_mutation(unit_class) {
        return Vec::new();
    }
    if record_ref.filter(|s| !s.is_empty()).is_some()
        && pubkey_ref.filter(|s| !s.is_empty()).is_some()
    {
        return Vec::new();
    }
    let uc = unit_class.unwrap_or("report-only");
    let base = m.get("base_sha").and_then(|v| v.as_str()).unwrap_or("");
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    if !base.is_empty() && base == head {
        return vec![format!(
            "{uc} unit declares base_sha == head_sha ({base}) and carries no signed dispatch record. An empty range asserts that this unit changed nothing and gives the gate no diff to check that against — a claim, not evidence, from the same worker that chose the class. Name the range the report covers, or have the coordinator sign the downgrade (#310)"
        )];
    }
    let prod = match production_changes(ctx, base, head) {
        Ok(p) => p,
        Err(e) => {
            return vec![format!(
                "{uc} unit with no signed dispatch record, and its shape cannot be determined: {e}. Pin base_sha and head_sha so the claim can be measured against the change, or have the coordinator sign the downgrade (#310)"
            )];
        }
    };
    if !prod.is_empty() {
        let mut sorted = prod;
        sorted.sort();
        return vec![format!(
            "{uc} unit changed code {sorted:?} and carries no signed dispatch record. unit_class arrives from the environment the worker controls, so this single value drops the negative control, the intent packet, lighting legality and reviewer_mode from a unit that changed behaviour. Verify it as a mutation, or have the coordinator sign the downgrade (#310)"
        )];
    }
    vec![format!(
        "NOTE: {uc} (unsupervised) — claimed with no signed dispatch record. base_sha..head_sha changes prose (docs) only, so the class is consistent with the change, but nothing off-worker authorized it (#310)"
    )]
}

fn check_replay_request(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    is_mut: bool,
    execute_nc: bool,
    nc_command: Option<&str>,
) -> Vec<String> {
    if !is_mut || !execute_nc {
        return Vec::new();
    }
    let nc = m
        .data
        .get("negative_control")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let tool = nc.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let raw_art = nc
        .get("artifact")
        .and_then(|v| v.as_str())
        .and_then(|a| read_artifact(ctx, m, a).ok());
    if !EXECUTABLE_NC_TOOLS.contains(&tool) || unreplayable_tool(tool, raw_art.as_deref()) {
        return vec![format!(
            "--execute-nc: no replay is implemented for negative_control.tool {tool:?} — only {EXECUTABLE_NC_TOOLS:?} can be re-executed here; fail-closed (#255)"
        )];
    }
    match nc_command_argv(ctx, &nc, nc_command) {
        Ok(_) => Vec::new(),
        Err(e) => vec![format!("--execute-nc: {e}")],
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerifyArgs {
    pub manifest: String,
    pub contract_source: Option<String>,
    pub contract_digest: Option<String>,
    pub repo: Option<String>,
    pub provenance: Option<String>,
    pub nc_command: Option<String>,
    pub execute_nc: bool,
    pub allow_static_nc: bool,
    pub base: Option<String>,
    pub symbol: Option<String>,
    pub unit_class: Option<String>,
    pub no_gh: bool,
    pub lighting: Option<String>,
    pub lane: Option<String>,
    pub dispatch_record: Option<String>,
    pub dispatch_pubkey: Option<String>,
    pub git_dir: Option<String>,
    pub evidence_root: Option<String>,
    pub retention_pubkey: Option<String>,
    pub transcript_out: Option<String>,
    pub transcript_key: Option<String>,
}

fn find_scripts_dir() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("OPEN_FLEET_ROOT") {
        let p = PathBuf::from(explicit).join("runtime/scripts");
        if p.is_dir() {
            return Some(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent();
        while let Some(d) = cur {
            let p = d.join("runtime/scripts");
            if p.join("verify.py").is_file() {
                return Some(p);
            }
            cur = d.parent();
        }
    }
    if let Ok(cwd) = env::current_dir() {
        let p = cwd.join("runtime/scripts");
        if p.join("verify.py").is_file() {
            return Some(p);
        }
    }
    None
}

fn hash_toolchain_files() -> BTreeMap<String, Value> {
    let dir = find_scripts_dir();
    let mut files = BTreeMap::new();
    for &name in TOOLCHAIN_FILES {
        let val = dir
            .as_ref()
            .and_then(|d| fs::read(d.join(name)).ok())
            .map(|b| Value::String(sha256_hex(&b)))
            .unwrap_or(Value::Null);
        files.insert(name.to_string(), val);
    }
    files
}

struct TranscriptInput<'a> {
    args: &'a VerifyArgs,
    exit_code: i32,
    fatal: &'a [String],
    notes: &'a [String],
    raw: Option<&'a [u8]>,
    files: &'a BTreeMap<String, Value>,
    skip_git: bool,
}

fn build_transcript(ctx: &VerifyCtx, input: &TranscriptInput<'_>) -> Map<String, Value> {
    let TranscriptInput {
        args,
        exit_code,
        fatal,
        notes,
        raw,
        files,
        skip_git,
    } = *input;
    let (manifest_sha, unit) = match raw {
        Some(bytes) => {
            let sha = Value::String(sha256_hex(bytes));
            let u = serde_json::from_slice::<Value>(bytes)
                .ok()
                .and_then(|v| v.get("unit").cloned())
                .unwrap_or(Value::Null);
            (sha, u)
        }
        None => (Value::Null, Value::Null),
    };
    let git_version = if !skip_git {
        if let Some(git) = ctx.git_bin.as_deref() {
            let (c, o, _) = run_proc_bytes(
                git,
                &[OsString::from("--version")],
                None,
                &ctx.git_env(),
                None,
                10,
            );
            let s = String::from_utf8_lossy(&o).trim().to_string();
            if c == 0 && !s.is_empty() {
                Value::String(s)
            } else {
                Value::Null
            }
        } else {
            Value::Null
        }
    } else {
        Value::Null
    };
    let mut files_map = Map::new();
    for (k, v) in files {
        files_map.insert(k.clone(), v.clone());
    }
    let verify_sha = files.get("verify.py").cloned().unwrap_or(Value::Null);
    let args_val = json!({
        "contract_source": args.contract_source,
        "contract_digest": args.contract_digest,
        "repo": args.repo,
        "base": args.base,
        "symbol": args.symbol,
        "execute_nc": args.execute_nc,
        "allow_static_nc": args.allow_static_nc,
        "unit_class": args.unit_class,
        "no_gh": args.no_gh,
        "lighting": args.lighting,
        "lane": args.lane,
        "dispatch_record": args.dispatch_record,
        "dispatch_pubkey": args.dispatch_pubkey,
        "nc_command": args.nc_command,
        "git_dir": args.git_dir,
        "evidence_root": args.evidence_root,
        "provenance": args.provenance,
        "retention_pubkey": args.retention_pubkey,
    });
    let mut rec = Map::new();
    rec.insert("unit".to_string(), unit);
    rec.insert("manifest".to_string(), Value::String(args.manifest.clone()));
    rec.insert("manifest_sha256".to_string(), manifest_sha);
    rec.insert("args".to_string(), args_val);
    rec.insert("fatal".to_string(), json!(fatal));
    rec.insert("notes".to_string(), json!(notes));
    rec.insert("exit".to_string(), json!(exit_code));
    rec.insert(
        "toolchain".to_string(),
        json!({
            "python": format!("rust-{}", env!("CARGO_PKG_VERSION")),
            "git": git_version,
            "verify_sha256": verify_sha,
            "files": Value::Object(files_map),
        }),
    );
    rec.insert(
        "timestamp".to_string(),
        Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, false)),
    );
    rec
}

fn write_transcript(out_ref: &str, record: &Map<String, Value>, seed: Option<&[u8; 32]>) -> bool {
    let payload: Value = if let Some(s) = seed {
        let missing: Vec<&str> = TRANSCRIPT_FIELDS
            .iter()
            .copied()
            .filter(|k| record.get(*k).map(|v| v.is_null()).unwrap_or(true))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "verify: transcript not signed — the verdict object is missing {missing:?}, and signing an absence binds nothing (dispatch-sign.py refuses the same)"
            );
            return false;
        }
        let msg = canonical_record(record, TRANSCRIPT_FIELDS);
        let sig = sign_bytes(s, &msg);
        let _ = publickey_bytes(s);
        json!({
            "record": Value::Object(record.clone()),
            "sig_b64": b64_encode(&sig),
        })
    } else {
        Value::Object(record.clone())
    };
    let out = Path::new(out_ref);
    if let Some(p) = out.parent() {
        if !p.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(p) {
                eprintln!("verify: could not write transcript {out_ref}: {e}");
                return false;
            }
        }
    }
    let pretty = match serde_json::to_string_pretty(&payload) {
        Ok(s) => format!("{s}\n"),
        Err(e) => {
            eprintln!("verify: could not write transcript {out_ref}: {e}");
            return false;
        }
    };
    if let Err(e) = fs::write(out, pretty) {
        eprintln!("verify: could not write transcript {out_ref}: {e}");
        return false;
    }
    true
}

fn validate_root_arg(
    ctx: &VerifyCtx,
    flag: &str,
    value: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    let Some(v) = value else {
        return Ok(None);
    };
    let p = Path::new(v);
    if !p.is_dir() {
        return Err(format!("{flag}: not a directory: {v}"));
    }
    let resolved = fs::canonicalize(p).map_err(|e| format!("{flag}: {e}"))?;
    let Some(git) = ctx.git_bin.as_deref() else {
        return Err(format!("{flag}: git unavailable"));
    };
    let args = vec![
        OsString::from("-C"),
        resolved.as_os_str().to_os_string(),
        OsString::from("rev-parse"),
        OsString::from("--is-inside-work-tree"),
    ];
    let (code, out_b, _) = run_proc_bytes(git, &args, None, &ctx.git_env(), None, 20);
    if code != 0 || String::from_utf8_lossy(&out_b).trim() != "true" {
        return Err(format!(
            "{flag}: '{v}' is not inside a git work tree — evidence no auditor can re-derive from a clone is refused (#267)"
        ));
    }
    Ok(Some(resolved))
}

pub fn evaluate_args(args: &VerifyArgs) -> (i32, Vec<String>, Vec<String>, Option<Vec<u8>>) {
    let mut ctx = VerifyCtx::new();
    ctx.roots_git = args
        .git_dir
        .as_deref()
        .and_then(|s| fs::canonicalize(s).ok())
        .filter(|p| p.is_dir());
    ctx.roots_evidence = args
        .evidence_root
        .as_deref()
        .and_then(|s| fs::canonicalize(s).ok())
        .filter(|p| p.is_dir());
    ctx.pin_git();
    if ctx.git_bin.is_none() {
        return (
            1,
            vec!["dependency: git not on PATH".to_string()],
            Vec::new(),
            None,
        );
    }
    let mut seed: Option<[u8; 32]> = None;
    if args.transcript_key.is_some() {
        if args.transcript_out.is_none() {
            return (
                1,
                vec![
                    "usage: --transcript-key requires --transcript-out (nothing to sign)"
                        .to_string(),
                ],
                Vec::new(),
                None,
            );
        }
        if args.execute_nc {
            return (
                1,
                vec![
                    "usage: --transcript-key cannot be combined with --execute-nc — the control runs worker code in the process that holds the seed. Sign after the control, in a process that never ran it: --transcript-out alone, then dispatch-sign.py sign-transcript; or a second verify.py invocation without --execute-nc".to_string(),
                ],
                Vec::new(),
                None,
            );
        }
    }

    let early_lane: Option<String> = match args.provenance.as_deref() {
        Some(p) if SOUND_PROVENANCE.contains(&p) => Some(format!("provenance={p}")),
        _ => match (
            args.dispatch_record.as_deref().filter(|s| !s.is_empty()),
            args.dispatch_pubkey.as_deref().filter(|s| !s.is_empty()),
        ) {
            (Some(_), Some(pk)) if ctx.key_source(pk, "--dispatch-pubkey", false).2 => {
                Some("enforcement (signed dispatch record + pubkey)".to_string())
            }
            _ => None,
        },
    };
    if let Some(el) = early_lane {
        if ctx.git_custody.as_deref() != Some("system") {
            ctx.lane = Some(el.clone());
            let git_s = ctx
                .git_bin
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let cust_s = ctx.git_custody.as_deref().unwrap_or("");
            let msg = format!(
                "authority: git at {git_s} is {cust_s} — a lane claiming soundness ({el}) cannot take its commit, tree and ancestry facts from a binary the graded worker could have replaced; fail-closed (h409 R2)"
            );
            let raw_m = fs::read(&args.manifest).ok();
            if let Some(ref tout) = args.transcript_out {
                let files = hash_toolchain_files();
                let rec = build_transcript(
                    &ctx,
                    &TranscriptInput {
                        args,
                        exit_code: 2,
                        fatal: std::slice::from_ref(&msg),
                        notes: &[],
                        raw: raw_m.as_deref(),
                        files: &files,
                        skip_git: true,
                    },
                );
                let _ = write_transcript(tout, &rec, None);
            }
            return (2, vec![msg], Vec::new(), raw_m);
        }
    }

    if let Some(ref tk) = args.transcript_key {
        match read_seed(Some(Path::new(tk))) {
            Ok(s) => seed = Some(s),
            Err(e) => {
                return (
                    1,
                    vec![format!("usage: --transcript-key: {e}")],
                    Vec::new(),
                    None,
                )
            }
        }
    }

    let mut root_errs = Vec::new();
    let gd = match validate_root_arg(&ctx, "--git-dir", args.git_dir.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            root_errs.push(format!("usage: {e}"));
            None
        }
    };
    let er = match validate_root_arg(&ctx, "--evidence-root", args.evidence_root.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            root_errs.push(format!("usage: {e}"));
            None
        }
    };
    if !root_errs.is_empty() {
        return (1, root_errs, Vec::new(), None);
    }
    ctx.roots_git = gd;
    ctx.roots_evidence = er;
    ctx.split_cache = None;
    ctx.discovery_cache.clear();

    let enforcement = match (
        args.dispatch_record.as_deref().filter(|s| !s.is_empty()),
        args.dispatch_pubkey.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(_), Some(pk)) => ctx.key_source(pk, "--dispatch-pubkey", true).2,
        _ => false,
    };
    let repo = ctx.resolve(
        args.provenance.as_deref(),
        enforcement,
        args.repo.as_deref(),
    );
    let toolchain = hash_toolchain_files();

    let mut m = match load_manifest(&args.manifest) {
        Ok(man) => man,
        Err(load_err) => {
            let mut fatal = vec![load_err];
            let post_tc = hash_toolchain_files();
            let drift: Vec<String> = post_tc
                .iter()
                .filter(|(k, v)| toolchain.get(*k) != Some(*v))
                .map(|(k, _)| k.clone())
                .collect();
            if !drift.is_empty() {
                fatal.push(format!(
                    "toolchain changed during this run: {drift:?} no longer hash as they did when the verifier started — worker code (the executed control) ran in between, so the verdict was not reached by the verifier a transcript would name; fail-closed (W3-11)"
                ));
            }
            if let Some(ref tout) = args.transcript_out {
                let rec = build_transcript(
                    &ctx,
                    &TranscriptInput {
                        args,
                        exit_code: 2,
                        fatal: &fatal,
                        notes: &[],
                        raw: None,
                        files: &toolchain,
                        skip_git: false,
                    },
                );
                let _ = write_transcript(tout, &rec, seed.as_ref());
            }
            return (2, fatal, Vec::new(), None);
        }
    };
    let raw_manifest = m.raw.clone();

    let is_mut = is_mutation(args.unit_class.as_deref());
    let corroborated = args
        .contract_source
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        && args
            .contract_digest
            .as_deref()
            .is_some_and(|s| !s.is_empty());
    let mut fatal: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    fn push_lines(lines: Vec<String>, fatal: &mut Vec<String>, notes: &mut Vec<String>) {
        for line in lines {
            if line.starts_with("NOTE:") {
                notes.push(line);
            } else {
                fatal.push(line);
            }
        }
    }

    if let Some(ref uc) = args.unit_class {
        if !UNIT_CLASSES.contains(&uc.as_str()) {
            notes.push(format!(
                "NOTE: unknown unit class {uc:?} — expected one of ['mutation', 'planning', 'report-only']; failing safe to mutation-strict checks (#178)"
            ));
        }
    }

    // Adopt lane/lighting from a verified signed dispatch record if omitted on CLI
    let mut eff_lane = args.lane.clone();
    let mut eff_lighting = args.lighting.clone();
    if args
        .dispatch_record
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        && args
            .dispatch_pubkey
            .as_deref()
            .is_some_and(|s| !s.is_empty())
        && (eff_lane.is_none() || eff_lighting.is_none())
    {
        let verdict = check_dispatch_provenance(
            &mut ctx,
            &mut m,
            &DispatchProvOpts {
                contract_digest: args.contract_digest.as_deref(),
                unit_class: args.unit_class.as_deref(),
                lighting: eff_lighting.as_deref(),
                record_ref: args.dispatch_record.as_deref(),
                pubkey_ref: args.dispatch_pubkey.as_deref(),
                no_gh: args.no_gh,
                lane: eff_lane.as_deref(),
                execute_nc: args.execute_nc,
                allow_static_nc: args.allow_static_nc,
            },
        );
        if verdict.iter().all(|l| l.starts_with("NOTE:")) {
            if let (Some(rec_b), None) =
                ctx.read_source(args.dispatch_record.as_deref().unwrap_or(""))
            {
                if let Ok(parsed) = serde_json::from_slice::<Value>(&rec_b) {
                    if let Some(signed) = parsed.get("record").and_then(|v| v.as_object()) {
                        if eff_lane.is_none() {
                            eff_lane = signed
                                .get("lane")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                        if eff_lighting.is_none() {
                            eff_lighting = signed
                                .get("lighting")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                }
            }
        }
    }

    push_lines(ctx.authority_leg(), &mut fatal, &mut notes);
    push_lines(
        check_scope(
            &ctx,
            &m.data,
            args.contract_source.as_deref(),
            args.contract_digest.as_deref(),
        ),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_oracle_scope(
            &mut ctx,
            &mut m,
            args.contract_source.as_deref(),
            args.contract_digest.as_deref(),
        ),
        &mut fatal,
        &mut notes,
    );
    push_lines(check_shas_present(&m.data), &mut fatal, &mut notes);
    push_lines(
        check_real_commits(&ctx, &m.data, is_mut),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_ancestry(&ctx, &m.data, args.base.as_deref()),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_base_binding(&ctx, &m.data, args.base.as_deref(), args.execute_nc),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_dispatch_provenance(
            &mut ctx,
            &mut m,
            &DispatchProvOpts {
                contract_digest: args.contract_digest.as_deref(),
                unit_class: args.unit_class.as_deref(),
                lighting: eff_lighting.as_deref(),
                record_ref: args.dispatch_record.as_deref(),
                pubkey_ref: args.dispatch_pubkey.as_deref(),
                no_gh: args.no_gh,
                lane: eff_lane.as_deref(),
                execute_nc: args.execute_nc,
                allow_static_nc: args.allow_static_nc,
            },
        ),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_class_downgrade(
            &ctx,
            &m.data,
            args.unit_class.as_deref(),
            args.dispatch_record.as_deref(),
            args.dispatch_pubkey.as_deref(),
        ),
        &mut fatal,
        &mut notes,
    );
    push_lines(check_freshness(&ctx, &m.data), &mut fatal, &mut notes);
    push_lines(
        check_commands(&ctx, &m.data, is_mut, args.nc_command.as_deref()),
        &mut fatal,
        &mut notes,
    );
    push_lines(check_redaction(&mut ctx, &mut m), &mut fatal, &mut notes);
    push_lines(check_intent(&m.data, is_mut), &mut fatal, &mut notes);
    push_lines(
        check_lighting(
            &m.data,
            is_mut,
            eff_lighting.as_deref(),
            eff_lane.as_deref(),
        ),
        &mut fatal,
        &mut notes,
    );
    push_lines(check_reviewer_mode(&m.data, is_mut), &mut fatal, &mut notes);
    push_lines(check_provenance(&m.data), &mut fatal, &mut notes);
    push_lines(
        check_retention_receipt(&ctx, &m, args.retention_pubkey.as_deref()),
        &mut fatal,
        &mut notes,
    );
    push_lines(
        check_replay_request(
            &mut ctx,
            &mut m,
            is_mut,
            args.execute_nc,
            args.nc_command.as_deref(),
        ),
        &mut fatal,
        &mut notes,
    );

    let (nc_errs, nc_executed) = check_negative_control(
        &mut ctx,
        &mut m,
        is_mut,
        args.execute_nc && fatal.is_empty(),
        args.nc_command.as_deref(),
    );
    push_lines(nc_errs, &mut fatal, &mut notes);

    let oss_authorized = quiet_oss_authorized(
        &ctx,
        args.contract_source.as_deref(),
        args.contract_digest.as_deref(),
    );
    let rev_errs = check_review(
        &mut ctx,
        &mut m,
        &ReviewOpts {
            repo: repo.as_deref(),
            is_mut,
            no_gh: args.no_gh,
            corroborated,
            dispatch_lighting: eff_lighting.as_deref(),
            nc_executed,
            allow_static_nc: args.allow_static_nc || (args.execute_nc && !fatal.is_empty()),
            oss_authorized,
        },
    );
    push_lines(rev_errs, &mut fatal, &mut notes);
    push_lines(
        check_symbol_on_base(&ctx, args.symbol.as_deref(), args.base.as_deref()),
        &mut fatal,
        &mut notes,
    );

    if is_mut && !nc_executed && fatal.is_empty() {
        notes.push(
            "NOTE: negative control corroborated from artifact only (--execute-nc not set) — static corroboration, not an executed control".to_string(),
        );
    }

    let post_tc = hash_toolchain_files();
    let drift: Vec<String> = post_tc
        .iter()
        .filter(|(k, v)| toolchain.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    if !drift.is_empty() {
        fatal.push(format!(
            "toolchain changed during this run: {drift:?} no longer hash as they did when the verifier started — worker code (the executed control) ran in between, so the verdict was not reached by the verifier a transcript would name; fail-closed (W3-11)"
        ));
    }

    let mut code = if fatal.is_empty() { 0 } else { 2 };
    if let Some(ref tout) = args.transcript_out {
        let rec = build_transcript(
            &ctx,
            &TranscriptInput {
                args,
                exit_code: code,
                fatal: &fatal,
                notes: &notes,
                raw: Some(&raw_manifest),
                files: &toolchain,
                skip_git: false,
            },
        );
        let written = write_transcript(tout, &rec, seed.as_ref());
        if !written && code == 0 {
            eprintln!(
                "verify: the requested transcript was not written — exit 1 (usage), the verdict above stands"
            );
            code = 1;
        }
    }
    (code, fatal, notes, Some(raw_manifest))
}

fn parse_raw_args(raw: &[OsString]) -> Result<Option<VerifyArgs>, String> {
    let mut out = VerifyArgs::default();
    let mut has_manifest = false;
    let mut i = 0usize;
    let take_val = |flag: &str, inline: Option<&str>, i: &mut usize| -> Result<String, String> {
        if let Some(v) = inline {
            Ok(v.to_string())
        } else if *i + 1 < raw.len() {
            *i += 1;
            Ok(raw[*i].to_string_lossy().into_owned())
        } else {
            Err(format!("argument {flag}: expected one argument"))
        }
    };
    while i < raw.len() {
        let tok = raw[i].to_string_lossy().into_owned();
        if tok == "-h" || tok == "--help" {
            println!(
                "usage: open-fleet verify --manifest MANIFEST [options]\n\n\
                 options:\n  \
                 -h, --help\n  \
                 --manifest MANIFEST\n  \
                 --contract-source CONTRACT_SOURCE\n  \
                 --contract-digest CONTRACT_DIGEST\n  \
                 --repo REPO\n  \
                 --provenance PROVENANCE\n  \
                 --nc-command NC_COMMAND\n  \
                 --execute-nc\n  \
                 --allow-static-nc\n  \
                 --base BASE\n  \
                 --symbol SYMBOL\n  \
                 --unit-class UNIT_CLASS\n  \
                 --no-gh\n  \
                 --lighting {{dark-eligible,lit}}\n  \
                 --lane {{A,B,0}}\n  \
                 --dispatch-record DISPATCH_RECORD\n  \
                 --dispatch-pubkey DISPATCH_PUBKEY\n  \
                 --git-dir GIT_DIR\n  \
                 --evidence-root EVIDENCE_ROOT\n  \
                 --retention-pubkey RETENTION_PUBKEY\n  \
                 --transcript-out TRANSCRIPT_OUT\n  \
                 --transcript-key TRANSCRIPT_KEY"
            );
            return Ok(None);
        }
        let (flag, inline) = match tok.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (tok.as_str(), None),
        };
        match flag {
            "--manifest" => {
                out.manifest = take_val(flag, inline, &mut i)?;
                has_manifest = true;
            }
            "--contract-source" => out.contract_source = Some(take_val(flag, inline, &mut i)?),
            "--contract-digest" => out.contract_digest = Some(take_val(flag, inline, &mut i)?),
            "--repo" => out.repo = Some(take_val(flag, inline, &mut i)?),
            "--provenance" => out.provenance = Some(take_val(flag, inline, &mut i)?),
            "--nc-command" => out.nc_command = Some(take_val(flag, inline, &mut i)?),
            "--execute-nc" => out.execute_nc = true,
            "--allow-static-nc" => out.allow_static_nc = true,
            "--base" => out.base = Some(take_val(flag, inline, &mut i)?),
            "--symbol" => out.symbol = Some(take_val(flag, inline, &mut i)?),
            "--unit-class" => out.unit_class = Some(take_val(flag, inline, &mut i)?),
            "--no-gh" => out.no_gh = true,
            "--lighting" => {
                let v = take_val(flag, inline, &mut i)?;
                if !LIGHTING_VALUES.contains(&v.as_str()) {
                    return Err(format!(
                        "argument --lighting: invalid choice: {v:?} (choose from 'dark-eligible', 'lit')"
                    ));
                }
                out.lighting = Some(v);
            }
            "--lane" => {
                let v = take_val(flag, inline, &mut i)?;
                if !matches!(v.as_str(), "A" | "B" | "0") {
                    return Err(format!(
                        "argument --lane: invalid choice: {v:?} (choose from 'A', 'B', '0')"
                    ));
                }
                out.lane = Some(v);
            }
            "--dispatch-record" => out.dispatch_record = Some(take_val(flag, inline, &mut i)?),
            "--dispatch-pubkey" => out.dispatch_pubkey = Some(take_val(flag, inline, &mut i)?),
            "--git-dir" => out.git_dir = Some(take_val(flag, inline, &mut i)?),
            "--evidence-root" => out.evidence_root = Some(take_val(flag, inline, &mut i)?),
            "--retention-pubkey" => out.retention_pubkey = Some(take_val(flag, inline, &mut i)?),
            "--transcript-out" => out.transcript_out = Some(take_val(flag, inline, &mut i)?),
            "--transcript-key" => out.transcript_key = Some(take_val(flag, inline, &mut i)?),
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }
    if !has_manifest {
        return Err("the following arguments are required: --manifest".to_string());
    }
    Ok(Some(out))
}

pub fn run_raw(raw: &[OsString]) -> i32 {
    let args = match parse_raw_args(raw) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(msg) => {
            eprintln!("verify: error: {msg}");
            return 2;
        }
    };
    let (code, fatal, notes, raw_m) = evaluate_args(&args);
    if code == 1 {
        for f in &fatal {
            eprintln!("{f}");
        }
        return 1;
    }
    for n in &notes {
        println!("{n}");
    }
    if !fatal.is_empty() {
        for f in &fatal {
            eprintln!("FAIL: {f}");
        }
        if raw_m.is_none() {
            eprintln!("verify: evidence manifest malformed/unreadable — unit is NOT done");
        } else {
            eprintln!(
                "verify: {} invariant(s) failed — unit is NOT done",
                fatal.len()
            );
        }
    } else if code == 0 {
        println!("verify: OK — all required checks passed");
    }
    code
}

pub fn verify_manifest_json(args: &VerifyArgs) -> (i32, Value) {
    let (code, fatal, notes, _) = evaluate_args(args);
    let payload = json!({
        "ok": code == 0,
        "exit_code": code,
        "manifest": args.manifest,
        "fatal": fatal,
        "notes": notes,
    });
    (code, payload)
}
