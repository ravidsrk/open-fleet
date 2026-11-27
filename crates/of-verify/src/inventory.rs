//! Native Rust port of `runtime/scripts/inventory.py`:
//! regenerate, verify, Ed25519-sign, and issue v1 retention receipts for
//! run-report SHA-256 integrity inventories (#315, #386, #608, #784).

use crate::base64_codec::{canonical_json, decode_strict, python_spaced_json};
use crate::dispatch_sign::{canonical_record, envelope, publickey_bytes, read_seed, verify_bytes};
use of_common::gitexec::run_git_repo;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

pub const EXIT_OK: i32 = 0;
pub const EXIT_MISMATCH: i32 = 1;
pub const EXIT_CANNOT_RUN: i32 = 2;

pub const SIGNATURE_TAG: &str = "inventory-signature";
pub const SIGNED_FIELDS: &[&str] = &["entries", "inventory_sha256"];
pub const RECEIPT_SCHEMA: &str = "open-fleet/retention-receipt/v1";
pub const RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "unit",
    "source_revision",
    "inventory",
    "inventory_sha256",
    "log_index",
    "entry_uuid",
    "signer",
];

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^\s{0,3}#{1,6}\s+.*\bintegrity inventory\s*\(sha256\)").expect("regex")
    })
}

fn next_heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s{0,3}#{1,6}\s+").expect("regex"))
}

fn fence_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*(```+|~~~+)").expect("regex"))
}

fn fence_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[ \t]{0,3}(`{3,}|~{3,})(.*)$").expect("regex"))
}

fn sha_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([0-9a-fA-F]{64})\s+(\S.*)$").expect("regex"))
}

fn table_row_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*\|(.+)\|\s*$").expect("regex"))
}

fn sha256_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{64}$").expect("regex"))
}

fn sha256_inline_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9a-fA-F]{64}").expect("regex"))
}

fn sig_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*<!--\s*inventory-signature\s+(\{.*\})\s*-->\s*$").expect("regex")
    })
}

fn receipt_source_rev_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$").expect("regex"))
}

fn receipt_inv_sha_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{64}$").expect("regex"))
}

fn receipt_entry_uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[0-9a-f]{16})?[0-9a-f]{64}$").expect("regex"))
}

fn receipt_signer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^ed25519:[0-9a-f]{64}$").expect("regex"))
}

#[derive(Debug, Clone)]
pub struct InventoryEntry {
    pub lineno: usize,
    pub path: String,
    pub recorded_hash: String,
    pub shape: &'static str,
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn repo_root(start: &Path) -> Option<PathBuf> {
    let out = run_git_repo(start, &["rev-parse", "--show-toplevel"], &[]).ok()?;
    if out.code != 0 {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn is_fence_close(line: &str, ch: char, flen: usize) -> bool {
    let trimmed_lead = line.trim_start_matches([' ', '\t']);
    let lead_len = line.len() - trimmed_lead.len();
    if lead_len > 3 {
        return false;
    }
    let trimmed = trimmed_lead.trim_end_matches([' ', '\t']);
    trimmed.len() >= flen && trimmed.chars().all(|c| c == ch)
}

pub fn find_blocks(lines: &[String]) -> Result<Vec<(usize, usize)>, String> {
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut fence: Option<(char, usize)> = None;
    for (i, line) in lines.iter().enumerate() {
        if let Some((ch, flen)) = fence {
            if is_fence_close(line, ch, flen) {
                fence = None;
            }
            continue;
        }
        if let Some(caps) = fence_open_re().captures(line) {
            let marker = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let rest = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let first = marker.chars().next().unwrap_or('`');
            if !(first == '`' && rest.contains('`')) {
                fence = Some((first, marker.len()));
                continue;
            }
        }
        if heading_re().is_match(line) {
            if let Some(cs) = current_start {
                blocks.push((cs, i));
            }
            current_start = Some(i);
        } else if current_start.is_some() && next_heading_re().is_match(line) {
            if let Some(cs) = current_start {
                blocks.push((cs, i));
            }
            current_start = None;
        }
    }
    if fence.is_some() {
        return Err("unclosed fenced code block in document".to_string());
    }
    if let Some(cs) = current_start {
        blocks.push((cs, lines.len()));
    }
    if blocks.is_empty() {
        return Err("no '## … integrity inventory (sha256)' heading found".to_string());
    }
    Ok(blocks)
}

pub fn parse_entries(
    lines: &[String],
    start: usize,
    end: usize,
) -> Result<Vec<InventoryEntry>, String> {
    let mut entries = Vec::new();
    for (offset, line) in lines[(start + 1)..end].iter().enumerate() {
        let idx = start + 1 + offset;
        if fence_re().is_match(line) {
            continue;
        }
        if let Some(caps) = sha_line_re().captures(line.trim()) {
            let h = caps[1].to_ascii_lowercase();
            let p = caps[2].trim().to_string();
            entries.push(InventoryEntry {
                lineno: idx,
                path: p,
                recorded_hash: h,
                shape: "fenced",
            });
            continue;
        }
        if let Some(caps) = table_row_re().captures(line) {
            let cells: Vec<String> = caps[1]
                .split('|')
                .map(|c| c.trim().trim_matches('`').trim().to_string())
                .collect();
            let all_sep = cells
                .iter()
                .all(|c| c.chars().all(|ch| matches!(ch, '-' | ':' | ' ')));
            if cells.len() < 2 || all_sep {
                continue;
            }
            let (path_cell, hash_cell) = (&cells[0], &cells[1]);
            if sha256_re().is_match(hash_cell) {
                entries.push(InventoryEntry {
                    lineno: idx,
                    path: path_cell.clone(),
                    recorded_hash: hash_cell.to_ascii_lowercase(),
                    shape: "table",
                });
            } else if sha256_re().is_match(path_cell) {
                entries.push(InventoryEntry {
                    lineno: idx,
                    path: hash_cell.clone(),
                    recorded_hash: path_cell.to_ascii_lowercase(),
                    shape: "table",
                });
            }
        }
    }
    if entries.is_empty() {
        return Err("the inventory block lists no <sha256> <path> entries".to_string());
    }
    Ok(entries)
}

pub fn resolve_entry(path_text: &str, report: &Path, root: Option<&Path>) -> Option<PathBuf> {
    let p = Path::new(path_text);
    if p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return None;
    }
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Some(r) = root {
        bases.push(r.to_path_buf());
    }
    bases.push(
        report
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    );

    for base in bases {
        let mut cur = base.clone();
        let mut has_symlink = false;
        for comp in p.components() {
            match comp {
                Component::CurDir => continue,
                Component::Normal(part) => {
                    cur.push(part);
                    if let Ok(meta) = fs::symlink_metadata(&cur) {
                        if meta.file_type().is_symlink() {
                            has_symlink = true;
                            break;
                        }
                    }
                }
                _ => {
                    has_symlink = true;
                    break;
                }
            }
        }
        if has_symlink {
            continue;
        }
        let candidate = base.join(p);
        let Ok(cmeta) = fs::symlink_metadata(&candidate) else {
            continue;
        };
        if cmeta.file_type().is_symlink() || !cmeta.is_file() {
            continue;
        }
        let (Ok(resolved_cand), Ok(resolved_base)) =
            (fs::canonicalize(&candidate), fs::canonicalize(&base))
        else {
            continue;
        };
        if !resolved_cand.starts_with(&resolved_base) {
            continue;
        }
        return Some(candidate);
    }
    None
}

pub fn sha256_at(rev: &str, path_text: &str, cwd: &Path) -> Option<String> {
    if rev.is_empty() || rev.starts_with('-') {
        return None;
    }
    let spec = format!("{rev}:{path_text}");
    let out = run_git_repo(cwd, &["cat-file", "blob", &spec], &[]).ok()?;
    if out.code != 0 {
        return None;
    }
    Some(hex::encode(Sha256::digest(&out.stdout)))
}

pub fn rev_exists(rev: &str, cwd: &Path) -> bool {
    if rev.is_empty() || rev.starts_with('-') {
        return false;
    }
    let spec = format!("{rev}^{{commit}}");
    run_git_repo(cwd, &["rev-parse", "--verify", "--quiet", &spec], &[])
        .map(|o| o.code == 0)
        .unwrap_or(false)
}

fn splitlines_py(text: &str) -> Vec<String> {
    let norm = text.replace("\r\n", "\n").replace('\r', "\n");
    let stripped = norm.strip_suffix('\n').unwrap_or(&norm);
    if stripped.is_empty() && norm.is_empty() {
        return Vec::new();
    }
    stripped.split('\n').map(|s| s.to_string()).collect()
}

pub fn load_report(
    report_path: &Path,
) -> Result<(PathBuf, Vec<String>, Vec<InventoryEntry>), String> {
    let text = fs::read_to_string(report_path)
        .map_err(|err| format!("{} is unreadable: {err}", report_path.display()))?;
    let lines = splitlines_py(&text);
    let blocks = find_blocks(&lines)?;
    let mut entries = Vec::new();
    for (start, end) in blocks {
        entries.extend(parse_entries(&lines, start, end)?);
    }
    Ok((report_path.to_path_buf(), lines, entries))
}

pub fn canonical_entries(entries: &[InventoryEntry]) -> Vec<u8> {
    let pairs: BTreeSet<(&str, &str)> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.recorded_hash.as_str()))
        .collect();
    let arr: Vec<Value> = pairs
        .into_iter()
        .map(|(p, h)| {
            Value::Array(vec![
                Value::String(p.to_string()),
                Value::String(h.to_string()),
            ])
        })
        .collect();
    canonical_json(&Value::Array(arr)).into_bytes()
}

pub fn inventory_digest(entries: &[InventoryEntry]) -> String {
    hex::encode(Sha256::digest(canonical_entries(entries)))
}

pub fn signature_record(entries: &[InventoryEntry]) -> Map<String, Value> {
    let unique: BTreeSet<(&str, &str)> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.recorded_hash.as_str()))
        .collect();
    let mut m = Map::new();
    m.insert("entries".to_string(), json!(unique.len()));
    m.insert(
        "inventory_sha256".to_string(),
        Value::String(inventory_digest(entries)),
    );
    m
}

pub type FoundSignature = Option<(usize, Map<String, Value>)>;

pub fn find_signature(lines: &[String]) -> Result<FoundSignature, String> {
    let blocks = find_blocks(lines)?;
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut stray: Vec<usize> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(caps) = sig_line_re().captures(line) {
            let inside = blocks.iter().any(|&(s, e)| idx > s && idx < e);
            if inside {
                found.push((idx, caps[1].to_string()));
            } else {
                stray.push(idx + 1);
            }
        }
    }
    if !stray.is_empty() {
        let joined: Vec<String> = stray.iter().map(|n| n.to_string()).collect();
        return Err(format!(
            "{SIGNATURE_TAG} line at line {} sits outside every inventory block — not an envelope; refused",
            joined.join(", ")
        ));
    }
    if found.is_empty() {
        return Ok(None);
    }
    if found.len() > 1 {
        return Err(format!(
            "{} {SIGNATURE_TAG} lines — a document carries one signature",
            found.len()
        ));
    }
    let (idx, raw) = &found[0];
    let val: Value = serde_json::from_str(raw)
        .map_err(|err| format!("the {SIGNATURE_TAG} line is not JSON: {err}"))?;
    let Some(map) = val.as_object() else {
        return Err(format!(
            "the {SIGNATURE_TAG} line is not a {{record, sig_b64}} envelope"
        ));
    };
    if !map.get("record").map(|v| v.is_object()).unwrap_or(false)
        || !map.get("sig_b64").map(|v| v.is_string()).unwrap_or(false)
    {
        return Err(format!(
            "the {SIGNATURE_TAG} line is not a {{record, sig_b64}} envelope"
        ));
    }
    Ok(Some((*idx, map.clone())))
}

pub fn read_pubkey(path: &Path) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("pubkey {} is unreadable or not hex: {err}", path.display()))?;
    let bytes = hex::decode(text.trim())
        .map_err(|err| format!("pubkey {} is unreadable or not hex: {err}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| format!("pubkey {} is not a 32-byte Ed25519 key", path.display()))
}

pub fn decode_signature(sig_b64: &str) -> Result<[u8; 64], String> {
    let sig = decode_strict(sig_b64).map_err(|err| format!("sig_b64 is malformed ({err})"))?;
    if sig.len() != 64 {
        return Err(format!(
            "sig_b64 is malformed (decodes to {} bytes, not a 64-byte Ed25519 signature)",
            sig.len()
        ));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig);
    Ok(arr)
}

pub fn verify_signature(
    env_map: &Map<String, Value>,
    entries: &[InventoryEntry],
    pub_bytes: &[u8; 32],
) -> Result<String, String> {
    let Some(record) = env_map.get("record").and_then(|v| v.as_object()) else {
        return Err("missing record object".to_string());
    };
    let want_digest = inventory_digest(entries);
    let rec_digest = record
        .get("inventory_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if rec_digest != want_digest {
        let got_pre = &rec_digest[..rec_digest.len().min(12)];
        let want_pre = &want_digest[..want_digest.len().min(12)];
        return Err(format!(
            "signature record binds inventory digest {got_pre}…, but the entries present digest to {want_pre}… — an entry was added, dropped or changed after signing"
        ));
    }
    let sig_b64 = env_map
        .get("sig_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sig = decode_signature(sig_b64)?;
    let msg = canonical_record(record, SIGNED_FIELDS);
    if !verify_bytes(&sig, &msg, pub_bytes) {
        return Err(
            "signature INVALID for this pubkey — not the coordinator's inventory (tampered, forged, or another key)"
                .to_string(),
        );
    }
    Ok(want_digest)
}

pub fn signature_line(seed: &[u8; 32], entries: &[InventoryEntry]) -> String {
    let rec = signature_record(entries);
    let env_val = envelope(seed, &rec, SIGNED_FIELDS);
    format!("<!-- {SIGNATURE_TAG} {} -->", python_spaced_json(&env_val))
}

fn place_signature(mut lines: Vec<String>, line: String) -> Result<Vec<String>, String> {
    if let Some((idx, _)) = find_signature(&lines)? {
        lines[idx] = line;
        return Ok(lines);
    }
    let blocks = find_blocks(&lines)?;
    let (start, end) = blocks[0];
    let mut at = end;
    while at > start + 1 && lines[at - 1].trim().is_empty() {
        at -= 1;
    }
    lines.insert(at, line);
    Ok(lines)
}

pub fn signer_id(pub_bytes: &[u8; 32]) -> String {
    format!("ed25519:{}", hex::encode(Sha256::digest(pub_bytes)))
}

pub fn parse_receipt(raw: &[u8]) -> Result<Map<String, Value>, String> {
    let text = std::str::from_utf8(raw).map_err(|err| format!("not readable JSON ({err})"))?;
    let val: Value =
        serde_json::from_str(text).map_err(|err| format!("not readable JSON ({err})"))?;
    let Some(env_map) = val.as_object() else {
        return Err("not a {record, sig_b64} envelope".to_string());
    };
    let Some(record) = env_map.get("record").and_then(|v| v.as_object()) else {
        return Err("not a {record, sig_b64} envelope".to_string());
    };

    for (where_s, present, allowed) in [
        ("envelope", env_map, &["record", "sig_b64"][..]),
        ("record", record, RECEIPT_FIELDS),
    ] {
        let mut extra: Vec<&str> = present
            .keys()
            .map(|k| k.as_str())
            .filter(|k| !allowed.contains(k))
            .collect();
        extra.sort();
        let keyish: Vec<&str> = extra
            .iter()
            .copied()
            .filter(|k| k.to_ascii_lowercase().contains("key"))
            .collect();
        if !keyish.is_empty() {
            return Err(format!(
                "the {where_s} declares {keyish:?} — a key inside a receipt never establishes trust; it is verified only against the key the verifier is handed (--retention-pubkey)"
            ));
        }
        if !extra.is_empty() {
            return Err(format!(
                "the {where_s} carries {extra:?}, outside the {RECEIPT_SCHEMA} shape — refused, not ignored"
            ));
        }
    }

    let missing: Vec<&str> = RECEIPT_FIELDS
        .iter()
        .copied()
        .filter(|&k| !record.contains_key(k))
        .collect();
    if !missing.is_empty() {
        return Err(format!("the record is missing {missing:?}"));
    }
    if !env_map
        .get("sig_b64")
        .map(|v| v.is_string())
        .unwrap_or(false)
    {
        return Err("sig_b64 is missing or not a string".to_string());
    }
    let schema = record.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema != RECEIPT_SCHEMA {
        return Err(format!(
            "schema {schema:?} is not {RECEIPT_SCHEMA:?} — this verifier reads v1 receipts only"
        ));
    }
    for field in ["unit", "inventory"] {
        let ok = record
            .get(field)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !ok {
            return Err(format!(
                "{field} must be a non-empty string, got {:?}",
                record.get(field)
            ));
        }
    }
    let log_idx_ok = match record.get("log_index") {
        Some(Value::Number(n)) => n.as_i64().map(|v| v >= 0).unwrap_or(false),
        _ => false,
    };
    if !log_idx_ok {
        return Err(format!(
            "log_index must be a non-negative integer, got {:?}",
            record.get("log_index")
        ));
    }
    let shapes: &[(&str, &Regex)] = &[
        ("source_revision", receipt_source_rev_re()),
        ("inventory_sha256", receipt_inv_sha_re()),
        ("entry_uuid", receipt_entry_uuid_re()),
        ("signer", receipt_signer_re()),
    ];
    for &(field, re) in shapes {
        let val_ok = record
            .get(field)
            .and_then(|v| v.as_str())
            .map(|s| re.is_match(s))
            .unwrap_or(false);
        if !val_ok {
            return Err(format!(
                "{field} {:?} is not in its v1 form",
                record.get(field)
            ));
        }
    }
    Ok(env_map.clone())
}

pub struct CheckOutcome {
    pub matched: Vec<String>,
    pub mismatched: Vec<(String, String, String)>,
    pub missing: Vec<String>,
}

pub fn check_entries(
    entries: &[InventoryEntry],
    report: &Path,
    root: Option<&Path>,
    at: Option<&str>,
) -> Result<CheckOutcome, String> {
    let mut matched = Vec::new();
    let mut mismatched = Vec::new();
    let mut missing = Vec::new();
    for e in entries {
        let actual = if let Some(rev) = at {
            let base = root.unwrap_or_else(|| report.parent().unwrap_or_else(|| Path::new(".")));
            let mut got = sha256_at(rev, &e.path, base);
            if got.is_none() {
                if let Some(r) = root {
                    if let (Ok(rep_dir), Ok(root_can)) = (
                        fs::canonicalize(report.parent().unwrap_or_else(|| Path::new("."))),
                        fs::canonicalize(r),
                    ) {
                        if let Ok(rel_dir) = rep_dir.strip_prefix(&root_can) {
                            let rel_posix = rel_dir.to_string_lossy().replace('\\', "/");
                            let joined = if rel_posix.is_empty() {
                                e.path.clone()
                            } else {
                                format!("{rel_posix}/{}", e.path)
                            };
                            got = sha256_at(rev, &joined, base);
                        }
                    }
                }
            }
            match got {
                Some(h) => h,
                None => {
                    missing.push(e.path.clone());
                    continue;
                }
            }
        } else {
            let Some(resolved) = resolve_entry(&e.path, report, root) else {
                missing.push(e.path.clone());
                continue;
            };
            sha256_file(&resolved)
                .map_err(|err| format!("{} could not be hashed: {err}", e.path))?
        };
        if actual == e.recorded_hash {
            matched.push(e.path.clone());
        } else {
            mismatched.push((e.path.clone(), e.recorded_hash.clone(), actual));
        }
    }
    Ok(CheckOutcome {
        matched,
        mismatched,
        missing,
    })
}

pub fn cmd_check(report_path: &Path, at: Option<&str>, pubkey: Option<&Path>) -> i32 {
    match cmd_check_inner(report_path, at, pubkey) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("inventory: could not run: {err}");
            EXIT_CANNOT_RUN
        }
    }
}

fn cmd_check_inner(
    report_path: &Path,
    at: Option<&str>,
    pubkey: Option<&Path>,
) -> Result<i32, String> {
    let (report, lines, entries) = load_report(report_path)?;
    let start = report
        .parent()
        .filter(|p| p.exists())
        .unwrap_or_else(|| Path::new("."));
    let root = repo_root(start);
    if let Some(rev) = at {
        let base = root
            .as_deref()
            .unwrap_or_else(|| report.parent().unwrap_or_else(|| Path::new(".")));
        if !rev_exists(rev, base) {
            return Err(format!("--at {rev} is not a commit in this repo"));
        }
    }
    let out = check_entries(&entries, &report, root.as_deref(), at)?;
    if out.matched.is_empty() && out.mismatched.is_empty() {
        let suffix = at.map(|r| format!(" at {r}")).unwrap_or_default();
        return Err(format!(
            "none of the {} listed path(s) exist{suffix} — nothing was verified; re-derive the hashes at the commit the report names",
            entries.len()
        ));
    }
    for (p, rec, act) in &out.mismatched {
        eprintln!("MISMATCH {p}\n  recorded {rec}\n  actual   {act}");
    }
    let where_s = match at {
        Some(r) => format!("the tree at {r}"),
        None => "the tree".to_string(),
    };
    for p in &out.missing {
        println!("MISSING  {p} (not present in {where_s} — not a mismatch)");
    }
    let at_suffix = at.map(|r| format!(" at {r}")).unwrap_or_default();
    println!(
        "inventory: {} verified, {} mismatched, {} missing, in {}{at_suffix}",
        out.matched.len(),
        out.mismatched.len(),
        out.missing.len(),
        report_path.display()
    );
    if let Some(pk_path) = pubkey {
        let pub_bytes = read_pubkey(pk_path)?;
        let sig_found = find_signature(&lines)?;
        let Some((_, env_map)) = sig_found else {
            eprintln!(
                "UNSIGNED inventory: no {SIGNATURE_TAG} line, and a pubkey is configured — refused; sign it with `inventory.py sign --key <seed>`"
            );
            return Ok(EXIT_MISMATCH);
        };
        let signed = match verify_signature(&env_map, &entries, &pub_bytes) {
            Ok(d) => d,
            Err(why) => {
                eprintln!("SIGNATURE {why}");
                return Ok(EXIT_MISMATCH);
            }
        };
        if signed != inventory_digest(&entries) {
            eprintln!(
                "SIGNATURE verifier returned {signed:?}, not this inventory's digest — refused"
            );
            return Ok(EXIT_MISMATCH);
        }
        let unit_word = if entries.len() == 1 {
            "entry"
        } else {
            "entries"
        };
        println!(
            "inventory: signature verified over {} {unit_word} (digest {}…) against {}",
            entries.len(),
            &signed[..signed.len().min(12)],
            pk_path.display()
        );
    }
    Ok(if out.mismatched.is_empty() {
        EXIT_OK
    } else {
        EXIT_MISMATCH
    })
}

pub fn cmd_write(report_path: &Path, dry_run: bool, key: Option<&Path>) -> i32 {
    match cmd_write_inner(report_path, dry_run, key) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("inventory: could not run: {err}");
            EXIT_CANNOT_RUN
        }
    }
}

fn cmd_write_inner(report_path: &Path, dry_run: bool, key: Option<&Path>) -> Result<i32, String> {
    let (report, mut lines, entries) = load_report(report_path)?;
    let start = report
        .parent()
        .filter(|p| p.exists())
        .unwrap_or_else(|| Path::new("."));
    let root = repo_root(start);
    let mut updated = 0usize;
    let mut absent = Vec::new();
    for e in &entries {
        let Some(resolved) = resolve_entry(&e.path, &report, root.as_deref()) else {
            absent.push(e.path.clone());
            continue;
        };
        let actual = sha256_file(&resolved)?;
        if actual == e.recorded_hash {
            continue;
        }
        lines[e.lineno] = sha256_inline_re()
            .replace(&lines[e.lineno], actual.as_str())
            .into_owned();
        updated += 1;
    }
    if !absent.is_empty() {
        for p in &absent {
            eprintln!("inventory: cannot hash {p} — it does not exist");
        }
        return Ok(EXIT_MISMATCH);
    }
    if dry_run {
        println!(
            "inventory: would update {updated} hash(es) in {}",
            report_path.display()
        );
        return Ok(EXIT_OK);
    }
    if let Some(key_path) = key {
        let mut fresh = Vec::with_capacity(entries.len());
        for e in &entries {
            let h = sha256_inline_re()
                .find(&lines[e.lineno])
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_else(|| e.recorded_hash.clone());
            fresh.push(InventoryEntry {
                lineno: e.lineno,
                path: e.path.clone(),
                recorded_hash: h,
                shape: e.shape,
            });
        }
        let seed = read_seed(Some(key_path))?;
        lines = place_signature(lines, signature_line(&seed, &fresh))?;
    } else if updated > 0 && matches!(find_signature(&lines), Ok(Some(_))) {
        let unit_word = if updated == 1 { "entry" } else { "entries" };
        eprintln!(
            "inventory: the {SIGNATURE_TAG} is now STALE ({updated} {unit_word} changed) — re-sign with `write --key` or `sign`"
        );
    }
    let out_text = format!("{}\n", lines.join("\n"));
    fs::write(&report, out_text)
        .map_err(|err| format!("{} could not be written: {err}", report_path.display()))?;
    let suffix = if key.is_some() { " and re-signed" } else { "" };
    println!(
        "inventory: updated {updated} hash(es) in {}{suffix}",
        report_path.display()
    );
    Ok(EXIT_OK)
}

pub fn cmd_sign(report_path: &Path, key: &Path) -> i32 {
    match cmd_sign_inner(report_path, key) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("inventory: could not run: {err}");
            EXIT_CANNOT_RUN
        }
    }
}

fn cmd_sign_inner(report_path: &Path, key: &Path) -> Result<i32, String> {
    let (report, lines, entries) = load_report(report_path)?;
    let start = report
        .parent()
        .filter(|p| p.exists())
        .unwrap_or_else(|| Path::new("."));
    let root = repo_root(start);
    let out = check_entries(&entries, &report, root.as_deref(), None)?;
    for (p, rec, act) in &out.mismatched {
        eprintln!("MISMATCH {p}\n  recorded {rec}\n  actual   {act}");
    }
    for p in &out.missing {
        eprintln!("MISSING  {p} — not on disk, so not attestable");
    }
    if !out.mismatched.is_empty() || !out.missing.is_empty() {
        eprintln!("inventory: refusing to sign — run `inventory.py write` first");
        return Ok(EXIT_MISMATCH);
    }
    let seed = read_seed(Some(key))?;
    let updated_lines = place_signature(lines, signature_line(&seed, &entries))?;
    fs::write(&report, format!("{}\n", updated_lines.join("\n")))
        .map_err(|err| format!("{} could not be written: {err}", report_path.display()))?;
    let digest = inventory_digest(&entries);
    let unit_word = if entries.len() == 1 {
        "entry"
    } else {
        "entries"
    };
    println!(
        "inventory: signed {} {unit_word} (digest {}…) in {}",
        entries.len(),
        &digest[..digest.len().min(12)],
        report_path.display()
    );
    Ok(EXIT_OK)
}

pub struct ReceiptArgs {
    pub report: PathBuf,
    pub key: PathBuf,
    pub unit: String,
    pub source_revision: String,
    pub log_index: i64,
    pub entry_uuid: String,
    pub out: Option<PathBuf>,
}

enum ReceiptErr {
    Inventory(String),
    Refused(String),
}

pub fn cmd_receipt(args: &ReceiptArgs) -> i32 {
    match cmd_receipt_inner(args) {
        Ok(code) => code,
        Err(ReceiptErr::Inventory(err)) => {
            eprintln!("inventory: could not run: {err}");
            EXIT_CANNOT_RUN
        }
        Err(ReceiptErr::Refused(err)) => {
            eprintln!("inventory: receipt not written — {err}");
            EXIT_CANNOT_RUN
        }
    }
}

fn cmd_receipt_inner(args: &ReceiptArgs) -> Result<i32, ReceiptErr> {
    let (report, lines, entries) = load_report(&args.report).map_err(ReceiptErr::Inventory)?;
    let start = report
        .parent()
        .filter(|p| p.exists())
        .unwrap_or_else(|| Path::new("."));
    let Some(root) = repo_root(start) else {
        return Err(ReceiptErr::Inventory(format!(
            "{} is not inside a git work tree — a receipt names its inventory repo-relative",
            args.report.display()
        )));
    };
    let out = check_entries(&entries, &report, Some(&root), None).map_err(ReceiptErr::Inventory)?;
    for (p, _, _) in &out.mismatched {
        eprintln!("STALE    {p} — the inventory no longer re-derives from disk");
    }
    for p in &out.missing {
        eprintln!("STALE    {p} — the inventory no longer re-derives from disk");
    }
    if !out.mismatched.is_empty() || !out.missing.is_empty() {
        eprintln!(
            "inventory: refusing to write a receipt — run `inventory.py write` and `sign` first"
        );
        return Ok(EXIT_MISMATCH);
    }
    let seed = read_seed(Some(&args.key)).map_err(ReceiptErr::Inventory)?;
    let pub_bytes = publickey_bytes(&seed);
    let sig_found = find_signature(&lines).map_err(ReceiptErr::Inventory)?;
    let Some((_, env_map)) = sig_found else {
        eprintln!(
            "inventory: refusing to write a receipt — {} carries no {SIGNATURE_TAG}; a receipt binds a SIGNED inventory (`inventory.py sign --key <seed>`)",
            args.report.display()
        );
        return Ok(EXIT_MISMATCH);
    };
    let signed = match verify_signature(&env_map, &entries, &pub_bytes) {
        Ok(d) => d,
        Err(why) => {
            eprintln!(
                "inventory: refusing to write a receipt — the inventory signature does not hold under this seed's key: {why}"
            );
            return Ok(EXIT_MISMATCH);
        }
    };
    let rep_can = fs::canonicalize(&report).map_err(|e| {
        ReceiptErr::Inventory(format!("{} could not be resolved: {e}", report.display()))
    })?;
    let root_can = fs::canonicalize(&root).map_err(|e| {
        ReceiptErr::Inventory(format!("{} could not be resolved: {e}", root.display()))
    })?;
    let rel = rep_can
        .strip_prefix(&root_can)
        .map_err(|_| {
            ReceiptErr::Inventory(format!(
                "{} is outside the repository at {}",
                args.report.display(),
                root.display()
            ))
        })?
        .to_string_lossy()
        .replace('\\', "/");

    let mut rec = Map::new();
    rec.insert(
        "schema".to_string(),
        Value::String(RECEIPT_SCHEMA.to_string()),
    );
    rec.insert("unit".to_string(), Value::String(args.unit.clone()));
    rec.insert(
        "source_revision".to_string(),
        Value::String(args.source_revision.clone()),
    );
    rec.insert("inventory".to_string(), Value::String(rel.clone()));
    rec.insert(
        "inventory_sha256".to_string(),
        Value::String(signed.clone()),
    );
    rec.insert("log_index".to_string(), json!(args.log_index));
    rec.insert(
        "entry_uuid".to_string(),
        Value::String(args.entry_uuid.clone()),
    );
    rec.insert("signer".to_string(), Value::String(signer_id(&pub_bytes)));

    let receipt = envelope(&seed, &rec, RECEIPT_FIELDS);
    let compact = serde_json::to_vec(&receipt).unwrap_or_default();
    parse_receipt(&compact).map_err(ReceiptErr::Refused)?;

    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&receipt).unwrap_or_else(|_| "{}".to_string())
    );
    if let Some(ref out_path) = args.out {
        fs::write(out_path, &text).map_err(|err| {
            ReceiptErr::Inventory(format!(
                "{} could not be written: {err}",
                out_path.display()
            ))
        })?;
        println!(
            "inventory: wrote the {RECEIPT_SCHEMA} receipt for {rel} (digest {}…, log index {}) to {}",
            &signed[..signed.len().min(12)],
            args.log_index,
            out_path.display()
        );
    } else {
        print!("{text}");
    }
    Ok(EXIT_OK)
}
