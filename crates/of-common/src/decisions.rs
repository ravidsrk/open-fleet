//! DECISIONS ledger parsing, standing/active resolution, and native Ed25519 human-grant
//! verification, mirroring `runtime/scripts/decisions.py`.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

pub const SEP_CHAR: char = '·';
pub const GRANT_PUBKEY_REL: &str = ".orca/human-grant-pubkey";
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 300;
const CLASSES: &[&str] = &["mechanical", "taste", "one-way"];

const RESERVED_HUMAN_NAMES: &[&str] = &[
    "agent",
    "ai",
    "anonymous",
    "auto",
    "automatic",
    "bot",
    "coordinator",
    "fleet",
    "human",
    "model",
    "nobody",
    "none",
    "orca",
    "system",
    "unknown",
    "worker",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    pub ts: String,
    pub id: String,
    pub class: String,
    pub answer: String,
    pub why: String,
    pub task_id: String,
    pub raw: String,
}

fn ts_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}").expect("valid ts prefix regex"))
}

fn human_source_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\[source=human:([^\s\]]+?)(?: sig=([0-9a-fA-F]{128}))?\]\s*$")
            .expect("valid human source regex")
    })
}

fn human_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9._-]*$").expect("valid human name regex"))
}

fn secret_shapes() -> &'static [(&'static str, Regex)] {
    static SHAPES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SHAPES.get_or_init(|| {
        vec![
            (
                "aws-access-key",
                Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("regex"),
            ),
            (
                "github-token",
                Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}").expect("regex"),
            ),
            (
                "slack-token",
                Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}").expect("regex"),
            ),
            (
                "private-key-block",
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("regex"),
            ),
            (
                "bearer-literal",
                Regex::new(r"\b(Bearer|Authorization:)\s+[A-Za-z0-9._\-]{20,}").expect("regex"),
            ),
            (
                "provider-secret-key",
                Regex::new(r"\bsk-[A-Za-z0-9]{20,}").expect("regex"),
            ),
            (
                "assigned-secret",
                Regex::new(
                    r#"\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[=:]\s*["']?[A-Za-z0-9/+._\-]{12,}"#,
                )
                .expect("regex"),
            ),
        ]
    })
}

pub fn secret_hits(text: &str) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = secret_shapes()
        .iter()
        .filter(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
        .collect();
    hits.sort_unstable();
    hits.dedup();
    hits
}

pub fn redact_secrets(text: &str) -> String {
    let mut out = text.to_string();
    for (name, re) in secret_shapes() {
        let rep = format!("[REDACTED:{name}]");
        out = re.replace_all(&out, rep.as_str()).into_owned();
    }
    out
}

pub fn is_unicode_cf(ch: char) -> bool {
    let cp = ch as u32;
    matches!(
        cp,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

pub fn has_invisible_cf(text: &str) -> bool {
    text.chars().any(is_unicode_cf)
}

pub fn has_line_break(text: &str) -> bool {
    text.chars().any(|c| {
        matches!(
            c,
            '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{0085}' | '\x0b' | '\x0c'
        )
    })
}

pub fn parse_grant_pubkey(text: &str, where_label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim())
        .map_err(|err| format!("{where_label} is not a hex public key: {err}"))?;
    if bytes.len() != 32 {
        return Err(format!("{where_label} is not a 32-byte public key"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn parse_line(line: &str) -> Option<DecisionRecord> {
    if !line.contains(SEP_CHAR) {
        return None;
    }
    let trimmed = line.trim().trim_start_matches(['-', '*', '#', ' ']);
    let mut parts: Vec<String> = trimmed
        .split(SEP_CHAR)
        .map(|p| p.trim().to_string())
        .collect();
    if parts.len() < 5 {
        return None;
    }
    let ts_clean = parts[0].trim_matches('`').to_string();
    if !ts_prefix_re().is_match(&ts_clean) {
        return None;
    }
    parts[0] = ts_clean;
    let (why, task_id) = if parts.len() > 6 {
        (
            parts[4..parts.len() - 1].join(&SEP_CHAR.to_string()),
            parts[parts.len() - 1].clone(),
        )
    } else {
        (parts[4].clone(), parts.get(5).cloned().unwrap_or_default())
    };
    Some(DecisionRecord {
        ts: parts[0].clone(),
        id: parts[1].clone(),
        class: parts[2].clone(),
        answer: parts[3].clone(),
        why,
        task_id,
        raw: line.trim_end_matches('\n').to_string(),
    })
}

pub fn human_grant_of(record: &DecisionRecord) -> (Option<String>, Option<String>, String) {
    let why = &record.why;
    let Some(caps) = human_source_suffix_re().captures(why) else {
        return (None, None, why.clone());
    };
    let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let sig = caps.get(2).map(|m| m.as_str().to_ascii_lowercase());
    if !human_name_re().is_match(name)
        || RESERVED_HUMAN_NAMES.contains(&name.to_ascii_lowercase().as_str())
    {
        return (None, None, why.clone());
    }
    let start = caps.get(0).map(|m| m.start()).unwrap_or(why.len());
    let why_core = why[..start].trim_end().to_string();
    (Some(name.to_string()), sig, why_core)
}

pub fn grant_payload(
    ident: &str,
    answer: &str,
    why_core: &str,
    task_id: &str,
    ts: &str,
    klass: &str,
    source: Option<&str>,
) -> Vec<u8> {
    if let Some(src) = source {
        let canonical = if src.starts_with("human:") {
            src.to_string()
        } else {
            format!("human:{src}")
        };
        format!(
            "open-fleet human grant v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            ts, ident, klass, answer, why_core, task_id, canonical
        )
        .into_bytes()
    } else {
        format!(
            "open-fleet human grant v2\n{}\n{}\n{}\n{}\n{}\n{}",
            ts, ident, klass, answer, why_core, task_id
        )
        .into_bytes()
    }
}

pub fn instant(ts: &str) -> Option<DateTime<Utc>> {
    let clean = ts.trim().trim_matches('`');
    if clean.is_empty() {
        return None;
    }
    // RFC3339 / ISO-8601 with Z or numeric offset
    let with_offset =
        if let Some(stem) = clean.strip_suffix('Z').or_else(|| clean.strip_suffix('z')) {
            format!("{stem}+00:00")
        } else {
            clean.to_string()
        };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&with_offset) {
        return Some(dt.with_timezone(&Utc));
    }
    // Space separator with offset (Python fromisoformat accepts space between date and time)
    if let Some(idx) = with_offset.find(' ') {
        let t_form = format!("{}T{}", &with_offset[..idx], &with_offset[idx + 1..]);
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t_form) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // Naive datetime (treated as UTC)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(clean, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    // Date-only (YYYY-MM-DD -> 00:00:00 UTC)
    if let Ok(nd) = NaiveDate::parse_from_str(clean, "%Y-%m-%d") {
        if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

fn undated_sentinel() -> DateTime<Utc> {
    DateTime::<Utc>::MIN_UTC
}

pub fn recency(record: &DecisionRecord, position: usize) -> (DateTime<Utc>, usize) {
    (
        instant(&record.ts).unwrap_or_else(undated_sentinel),
        position,
    )
}

fn verify_ed25519(sig_hex: &str, payload: &[u8], pub_bytes: &[u8; 32]) -> bool {
    let Ok(sig_vec) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_vec.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    let Ok(vk) = VerifyingKey::from_bytes(pub_bytes) else {
        return false;
    };
    vk.verify(payload, &sig).is_ok()
}

pub fn validate_record(record: &DecisionRecord, grant_pub: Option<&[u8; 32]>) -> Vec<String> {
    let mut problems = Vec::new();
    if record.id.is_empty() {
        problems.push("empty gate-or-ask id".to_string());
    }
    if !CLASSES.contains(&record.class.as_str()) {
        problems.push(format!(
            "class {:?} is not one of {}",
            record.class,
            CLASSES.join(", ")
        ));
    }
    if record.answer.is_empty() {
        problems.push("empty answer".to_string());
    }
    if record.why.is_empty() {
        problems.push("empty why (a decision nobody can reconstruct is not a record)".to_string());
    }
    if has_invisible_cf(&record.raw)
        || [
            &record.ts,
            &record.id,
            &record.class,
            &record.answer,
            &record.why,
            &record.task_id,
        ]
        .iter()
        .any(|s| has_invisible_cf(s))
    {
        problems.push(
            "invisible format/bidi control character (Unicode Cf) in ledger record — refusing hidden text (#772)".to_string(),
        );
    }
    if has_line_break(&record.raw)
        || [
            &record.ts,
            &record.id,
            &record.class,
            &record.answer,
            &record.why,
            &record.task_id,
        ]
        .iter()
        .any(|s| has_line_break(s))
    {
        problems.push(
            "embedded carriage return or Unicode line break in ledger record — refusing line-break injection (one record, one line)".to_string(),
        );
    }
    match instant(&record.ts) {
        None => {
            problems.push(format!(
                "ts {:?} is not a readable timestamp — a record whose time cannot be read sorts before everything and would pass for history",
                record.ts
            ));
        }
        Some(dt) => {
            let ahead = (dt - Utc::now()).num_seconds();
            if ahead > MAX_FUTURE_SKEW_SECONDS {
                problems.push(format!(
                    "ts is {ahead}s in the future — active() ranks by ts, so a future stamp out-ranks every later decision on this id (P2-3)"
                ));
            }
        }
    }
    let shapes = secret_hits(&record.raw);
    if !shapes.is_empty() {
        problems.push(format!(
            "credential-shaped text ({}) — the log is permanent",
            shapes.join(", ")
        ));
    }
    if record.class != "one-way" {
        if let Some(caps) = human_source_suffix_re().captures(&record.why) {
            if caps.get(2).is_some() {
                problems.push(
                    "grant signature on a non-one-way line — a signed suffix only ever binds a one-way grant; refusing an unchecked signed-looking marker".to_string(),
                );
            }
        }
    }
    if record.class == "one-way" {
        let (name_opt, sig_opt, why_core) = human_grant_of(record);
        match (name_opt, sig_opt) {
            (None, _) => {
                problems.push(
                    "class one-way with no human source — the why must end with [source=human:<name>] recorded via append --source".to_string(),
                );
            }
            (Some(_), None) if grant_pub.is_some() => {
                problems.push(
                    "class one-way with no grant signature while a human grant pubkey is pinned (.orca/human-grant-pubkey) — every one-way line must carry a signature that verifies (sign-grant, then append --grant-sig)".to_string(),
                );
            }
            (Some(name), Some(sig)) => {
                if let Some(pub_bytes) = grant_pub {
                    let src = format!("human:{name}");
                    let p3 = grant_payload(
                        &record.id,
                        &record.answer,
                        &why_core,
                        &record.task_id,
                        &record.ts,
                        &record.class,
                        Some(&src),
                    );
                    let p2 = grant_payload(
                        &record.id,
                        &record.answer,
                        &why_core,
                        &record.task_id,
                        &record.ts,
                        &record.class,
                        None,
                    );
                    if !(verify_ed25519(&sig, &p3, pub_bytes)
                        || verify_ed25519(&sig, &p2, pub_bytes))
                    {
                        problems.push(
                            "grant signature does not verify against the pinned human grant pubkey for this line's ts/id/class/answer/why/task/source (payload v3/v2: a v1 signature, a spoofed source on v3, or one replayed under another ts does not)".to_string(),
                        );
                    }
                } else {
                    problems.push(
                        "carries a grant signature but no human grant pubkey is pinned (.orca/human-grant-pubkey) — a signature nothing can verify fails closed".to_string(),
                    );
                }
            }
            (Some(_), None) => {}
        }
    }
    problems
}

pub fn grant_problems(record: &DecisionRecord, grant_pub: Option<&[u8; 32]>) -> Vec<String> {
    let mut problems = Vec::new();
    if record.class != "one-way" {
        problems.push(format!(
            "class {:?} is not one-way — a grant is a one-way human decision",
            record.class
        ));
    }
    problems.extend(validate_record(record, grant_pub));
    problems
}

fn is_standing_malformed(record: &DecisionRecord) -> bool {
    if record.id.is_empty() || record.answer.is_empty() || record.why.is_empty() {
        return true;
    }
    if !CLASSES.contains(&record.class.as_str()) {
        return true;
    }
    let Some(dt) = instant(&record.ts) else {
        return true;
    };
    if (dt - Utc::now()).num_seconds() > MAX_FUTURE_SKEW_SECONDS {
        return true;
    }
    if has_invisible_cf(&record.raw)
        || [
            &record.ts,
            &record.id,
            &record.class,
            &record.answer,
            &record.why,
            &record.task_id,
        ]
        .iter()
        .any(|s| has_invisible_cf(s))
    {
        return true;
    }
    if has_line_break(&record.raw)
        || [
            &record.ts,
            &record.id,
            &record.class,
            &record.answer,
            &record.why,
            &record.task_id,
        ]
        .iter()
        .any(|s| has_line_break(s))
    {
        return true;
    }
    if record.class != "one-way" {
        if let Some(caps) = human_source_suffix_re().captures(&record.why) {
            if caps.get(2).is_some() {
                return true;
            }
        }
    }
    false
}

fn is_waiver_retirement(record: &DecisionRecord, prior_one_way: Option<&DecisionRecord>) -> bool {
    record.id.trim().starts_with("floor-waiver:")
        && record.answer.trim().eq_ignore_ascii_case("superseded")
        && prior_one_way
            .map(|p| p.answer.trim().eq_ignore_ascii_case("allow"))
            .unwrap_or(false)
}

fn valid_one_way(record: &DecisionRecord, grant_pub: Option<&[u8; 32]>) -> bool {
    record.class == "one-way" && grant_problems(record, grant_pub).is_empty()
}

pub fn standing(records: &[DecisionRecord], grant_pub: Option<&[u8; 32]>) -> Vec<DecisionRecord> {
    let mut survivors: Vec<(usize, &DecisionRecord)> = Vec::new();
    for (pos, r) in records.iter().enumerate() {
        if is_standing_malformed(r) {
            continue;
        }
        if r.class == "one-way" {
            if grant_pub.is_some() {
                if !grant_problems(r, grant_pub).is_empty() {
                    continue;
                }
            } else if human_grant_of(r).1.is_some() {
                continue;
            }
        }
        survivors.push((pos, r));
    }

    type RankedDecision<'a> = ((DateTime<Utc>, usize), &'a DecisionRecord);
    let mut one_way_by_id: HashMap<&str, Vec<RankedDecision<'_>>> = HashMap::new();
    for &(pos, r) in &survivors {
        if valid_one_way(r, grant_pub) {
            one_way_by_id
                .entry(r.id.as_str())
                .or_default()
                .push((recency(r, pos), r));
        }
    }
    for rows in one_way_by_id.values_mut() {
        rows.sort_by_key(|(k, _)| *k);
    }

    let mut out = Vec::new();
    for (pos, r) in survivors {
        if r.class != "one-way" {
            let my_key = recency(r, pos);
            if let Some(rows) = one_way_by_id.get(r.id.as_str()) {
                let prior: Vec<&DecisionRecord> = rows
                    .iter()
                    .filter(|(k, _)| *k < my_key)
                    .map(|(_, rec)| *rec)
                    .collect();
                if let Some(last_prior) = prior.last().copied() {
                    if !is_waiver_retirement(r, Some(last_prior)) {
                        continue;
                    }
                }
            }
        }
        out.push(r.clone());
    }
    out
}

pub fn active(records: &[DecisionRecord]) -> Vec<DecisionRecord> {
    let mut latest: HashMap<&str, ((DateTime<Utc>, usize), &DecisionRecord)> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for (pos, rec) in records.iter().enumerate() {
        let key = recency(rec, pos);
        match latest.get(rec.id.as_str()) {
            None => {
                order.push(rec.id.as_str());
                latest.insert(rec.id.as_str(), (key, rec));
            }
            Some((cur_key, _)) if key > *cur_key => {
                latest.insert(rec.id.as_str(), (key, rec));
            }
            _ => {}
        }
    }
    order
        .into_iter()
        .filter_map(|id| latest.get(id).map(|(_, r)| *r))
        .filter(|r| !r.answer.trim().eq_ignore_ascii_case("superseded"))
        .cloned()
        .collect()
}
