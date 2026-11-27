//! Base-ref waiver loading, scope matching, and malformed/refused waiver diagnostics,
//! mirroring `runtime/scripts/floor_guard.py:1009-1214`.

use crate::Finding;
use of_common::decisions::{self, DecisionRecord};

const WAIVER_ID_PREFIX: &str = "floor-waiver:";

pub fn path_waived_by(token: &str, path: &str) -> bool {
    if token == path {
        return true;
    }
    let Some(base) = token.strip_suffix("/**") else {
        return false;
    };
    let prefix: Vec<&str> = base.split('/').filter(|p| !p.is_empty()).collect();
    if prefix.is_empty() {
        return false;
    }
    let path_parts: Vec<&str> = path.split('/').collect();
    path_parts.len() >= prefix.len() && path_parts[..prefix.len()] == prefix[..]
}

fn waiver_records(
    waiver_lines: &[String],
    grant_pub: Option<&[u8; 32]>,
    verified_only: bool,
) -> Vec<DecisionRecord> {
    let mut records = Vec::new();
    for line in waiver_lines {
        if let Some(rec) = decisions::parse_line(line) {
            if rec.id.trim().starts_with(WAIVER_ID_PREFIX) {
                records.push(rec);
            }
        }
    }
    let filtered = if verified_only {
        decisions::standing(&records, grant_pub)
    } else {
        records
    };
    decisions::active(&filtered)
}

fn scoped_allows<'a>(finding: &Finding, records: &'a [DecisionRecord]) -> Vec<&'a DecisionRecord> {
    let mut out = Vec::new();
    for rec in records {
        if !rec.answer.trim().eq_ignore_ascii_case("allow") {
            continue;
        }
        let rest = &rec.id.trim()[WAIVER_ID_PREFIX.len()..];
        let Some((rule, scope)) = rest.split_once(':') else {
            continue;
        };
        if rule == finding.rule && path_waived_by(scope, &finding.path) {
            out.push(rec);
        }
    }
    out
}

pub fn is_waived(finding: &Finding, waiver_lines: &[String], grant_pub: Option<&[u8; 32]>) -> bool {
    if finding.path.is_empty() {
        return false;
    }
    let active = waiver_records(waiver_lines, grant_pub, true);
    for rec in scoped_allows(finding, &active) {
        if decisions::grant_problems(rec, grant_pub).is_empty() {
            return true;
        }
    }
    false
}

pub fn refused_waivers(
    finding: &Finding,
    waiver_lines: &[String],
    grant_pub: Option<&[u8; 32]>,
) -> Vec<(String, String)> {
    if finding.path.is_empty() {
        return Vec::new();
    }
    let newest = waiver_records(waiver_lines, grant_pub, false);
    let mut out = Vec::new();
    for rec in scoped_allows(finding, &newest) {
        let problems = decisions::grant_problems(rec, grant_pub);
        if !problems.is_empty() {
            out.push((rec.raw.clone(), problems.join("; ")));
        }
    }
    out
}

pub fn malformed_waivers(waiver_lines: &[String]) -> Vec<(String, String)> {
    let mut notes = Vec::new();
    for line in waiver_lines {
        let Some(rec) = decisions::parse_line(line) else {
            continue;
        };
        let ident = rec.id.trim();
        if ident == "floor-waiver" {
            notes.push((
                rec.raw,
                "its scope is not in the id — waivers carry it there now, so the ledger can retire one without retiring all of them".to_string(),
            ));
        } else if let Some(rest) = ident.strip_prefix(WAIVER_ID_PREFIX) {
            let valid = match rest.split_once(':') {
                Some((rule, scope)) => !rule.is_empty() && !scope.is_empty(),
                None => false,
            };
            if !valid {
                notes.push((
                    rec.raw,
                    "its id is not `floor-waiver:<rule>:<path-or-glob>`".to_string(),
                ));
            }
        }
    }
    notes
}
