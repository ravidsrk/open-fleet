//! Native Rust port of `runtime/scripts/decisions.py`:
//! durable governance log validation, active/standing resolution, lens tallies,
//! one-way door net matching, and native Ed25519 human grant keygen/signing.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use of_common::decisions::{
    active, grant_payload, grant_problems, has_invisible_cf, has_line_break, instant,
    parse_grant_pubkey, parse_line, recency, standing, validate_record, DecisionRecord,
    GRANT_PUBKEY_REL, MAX_FUTURE_SKEW_SECONDS, SEP_CHAR,
};
use of_common::gitexec;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

pub const EXIT_OK: i32 = 0;
pub const EXIT_VIOLATION: i32 = 1;
pub const EXIT_CANNOT_RUN: i32 = 2;

pub const DEFAULT_LOG: &str = "docs/DECISIONS.md";
pub const PRIMARY_DECISIONS_ENV: &str = "OPEN_FLEET_DECISIONS_FILE";
pub const DECISIONS_ENV: &str = "ORCA_DECISIONS_FILE";
const CLASSES: &[&str] = &["mechanical", "taste", "one-way"];
const NEVER_GATE: &[&str] = &["security", "privacy", "data-migration"];
const GATE_OFF_STREAK: usize = 10;

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

const FILLER: &[&str] = &[
    "the", "a", "an", "it", "this", "that", "these", "those", "our", "your", "their", "its",
];

fn human_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9._-]*$").expect("regex"))
}

fn human_source_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\[source=human:([^\s\]]+?)(?: sig=([0-9a-fA-F]{128}))?\]\s*$").expect("regex")
    })
}

fn ts_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}").expect("regex"))
}

fn since_date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("regex"))
}

fn sig128_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{128}$").expect("regex"))
}

fn zero_only_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^0+$").expect("regex"))
}

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9]+").expect("regex"))
}

fn forms_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        let groups: &[(&str, &[&str])] = &[
            ("merge", &["merges", "merged", "merging"]),
            ("deploy", &["deploys", "deployed", "deploying"]),
            ("ship", &["ships", "shipped", "shipping"]),
            ("release", &["releases", "released", "releasing"]),
            ("publish", &["publishes", "published", "publishing"]),
            ("promote", &["promotes", "promoted", "promoting"]),
            ("delete", &["deletes", "deleted", "deleting"]),
            ("drop", &["drops", "dropped", "dropping"]),
            ("rotate", &["rotates", "rotated", "rotating"]),
            ("revoke", &["revokes", "revoked", "revoking"]),
            ("erase", &["erases", "erased", "erasing"]),
            ("remove", &["removes", "removed", "removing"]),
            ("destroy", &["destroys", "destroyed", "destroying"]),
            ("wipe", &["wipes", "wiped", "wiped", "wiping"]),
            ("purge", &["purges", "purged", "purging"]),
            ("nuke", &["nukes", "nuked", "nuking"]),
            ("freeze", &["freezes", "froze", "freezing"]),
            (
                "unfreeze",
                &["unfreezes", "unfroze", "unfrozen", "unfreezing"],
            ),
            ("lift", &["lifts", "lifted", "lifting"]),
            ("land", &["lands", "landed", "landing"]),
            ("charge", &["charges", "charged", "charging"]),
            ("grant", &["grants", "granted", "granting"]),
            ("create", &["creates", "created", "creating"]),
            ("provision", &["provisions", "provisioned", "provisioning"]),
            ("revert", &["reverts", "reverted", "reverting"]),
            ("restore", &["restores", "restored", "restoring"]),
            ("approve", &["approves", "approved", "approving"]),
            ("close", &["closes", "closed", "closing"]),
            ("truncate", &["truncates", "truncated", "truncating"]),
            ("buy", &["buys", "bought", "buying"]),
            ("purchase", &["purchases", "purchased", "purchasing"]),
            ("upgrade", &["upgrades", "upgraded", "upgrading"]),
            ("increase", &["increases", "increased", "increasing"]),
            ("enable", &["enables", "enabled", "enabling"]),
            ("raise", &["raises", "raised", "raising"]),
            ("widen", &["widens", "widened", "widening"]),
            ("expand", &["expands", "expanded", "expanding"]),
            ("amend", &["amends", "amended", "amending"]),
            (
                "regenerate",
                &["regenerates", "regenerated", "regenerating"],
            ),
            ("reset", &["resets", "resetting"]),
            ("paste", &["pastes", "pasted", "pasting"]),
            ("commit", &["commits", "committed", "committing"]),
            ("bypass", &["bypasses", "bypassed", "bypassing"]),
            ("push", &["pushes", "pushed", "pushing"]),
            ("cut", &["cuts", "cutting"]),
            ("apply", &["applies", "applied", "applying"]),
            ("roll", &["rolls", "rolled", "rolling"]),
            ("take", &["takes", "took", "taken", "taking"]),
            ("go", &["goes", "went", "gone", "going"]),
            ("back", &["backs", "backed", "backing"]),
            ("empty", &["empties", "emptied", "emptying"]),
            ("tear", &["tears", "tore", "torn", "tearing"]),
            ("change", &["changes", "changed", "changing"]),
            ("add", &["adds", "added", "adding"]),
            ("use", &["uses", "used", "using"]),
            ("declare", &["declares", "declared", "declaring"]),
            ("sign", &["signs", "signed", "signing"]),
            ("reject", &["rejects", "rejected", "rejecting"]),
            ("decline", &["declines", "declined", "declining"]),
            ("post", &["posts", "posted", "posting"]),
            ("submit", &["submits", "submitted", "submitting"]),
            ("request", &["requests", "requested", "requesting"]),
            ("mark", &["marks", "marked", "marking"]),
            ("force", &["forces", "forced", "forcing"]),
            ("launch", &["launches", "launched", "launching"]),
            ("rollout", &["rollouts"]),
        ];
        for (base, forms) in groups {
            for f in *forms {
                m.insert(*f, *base);
            }
        }
        m
    })
}

fn is_combining_mark_mn(c: char) -> bool {
    let cp = c as u32;
    matches!(
        cp,
        0x0300..=0x036F
            | 0x0483..=0x0487
            | 0x0591..=0x05BD
            | 0x05BF
            | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5
            | 0x05C7
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0670
            | 0x06D6..=0x06DC
            | 0x06DF..=0x06E4
            | 0x06E7..=0x06E8
            | 0x06EA..=0x06ED
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0xFE00..=0xFE0F
            | 0xFE20..=0xFE2F
    )
}

fn normalize_text(text: &str) -> String {
    let stripped: String = text
        .nfkd()
        .filter(|&ch| !of_common::decisions::is_unicode_cf(ch) && !is_combining_mark_mn(ch))
        .collect();
    stripped.nfkc().collect()
}

fn canon_token(tok: &str) -> String {
    let mut t = forms_map().get(tok).copied().unwrap_or(tok);
    t = match t {
        "erase" | "wipe" | "destroy" | "remove" | "purge" | "nuke" => "delete",
        "launch" | "rollout" => "deploy",
        other => other,
    };
    if t.len() > 3 && t.ends_with('s') && !t.ends_with("ss") {
        t[..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

pub fn fold(text: &str) -> String {
    let norm = normalize_text(text).to_lowercase().replace(['-', '_'], " ");
    token_re()
        .find_iter(&norm)
        .map(|m| m.as_str())
        .filter(|t| !FILLER.contains(t))
        .map(canon_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn door_folded_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            ("merge-to-default", Regex::new(r"\b(?:merge|promote|land)\b(?:\s+[a-z0-9]+){1,4}\s+(?:to|into|on)\s+(?:main|master|default\s+branch)\b").expect("regex")),
            ("merge-to-default", Regex::new(r"\bforce\s+push\b(?:\s+[a-z0-9]+){0,4}\s+(?:main|master)\b").expect("regex")),
            ("deploy", Regex::new(r"\b(?:deploy|ship|release|promote|push|roll\s+out)\b(?:\s+[a-z0-9]+){1,4}\s+to\s+(?:prod|production)\b").expect("regex")),
            ("deploy", Regex::new(r"\bkubectl\s+apply\b(?:\s+[a-z0-9]+){0,4}\s+(?:prod|production)\b").expect("regex")),
            ("rollback", Regex::new(r"\b(?:roll\s*back|revert|back\s+out|restore)\b(?:\s+[a-z0-9]+){1,4}\s+(?:deploy|deployment|release|prod|production)\b").expect("regex")),
            ("deletion", Regex::new(r"\b(?:delete|drop|truncate|empty)\b(?:\s+[a-z0-9]+){1,3}\s+(?:database|db|table|bucket|repository|volume|environment|(?:default|main|master|base|protected|release|integration|unmerged)\s+branch|(?:dirty|coordinator)\s+worktree)\b").expect("regex")),
            ("secret-rotation", Regex::new(r"\b(?:rotate|revoke|regenerate|reset)\b(?:\s+[a-z0-9]+){1,3}\s+(?:credential|secret|key|token)\b").expect("regex")),
            ("live-credentials", Regex::new(r"\b(?:paste|commit|provision|create|use)\b(?:\s+[a-z0-9]+){0,3}\s+(?:live|prod|production)\s+(?:credential|secret|api\s+key|access\s+key|token)\b").expect("regex")),
            ("live-credentials", Regex::new(r"\bgrant\b(?:\s+[a-z0-9]+){0,2}\s+(?:prod|production)\s+access\b").expect("regex")),
            ("review-verdict", Regex::new(r"\b(?:approve|lgtm)\b(?:\s+[a-z0-9]+){1,3}\s+(?:pr|pull\s+request|merge\s+request)\b").expect("regex")),
            ("close-without-landing", Regex::new(r"\bclose\b(?:\s+[a-z0-9]+){0,3}\s+(?:pr|pull\s+request|issue|contribution)\b(?:\s+[a-z0-9]+){0,3}\s+(?:without\s+(?:landing|merging)|as\s+(?:refuted|duplicate|not\s+planned|wontfix|won\s+t\s+fix|invalid|stale))\b").expect("regex")),
            ("scope-change", Regex::new(r"\b(?:change|widen|expand|amend|drop|delete)\b(?:\s+[a-z0-9]+){0,3}\s+frozen\s+(?:scope|criterion|spec|denominator)\b").expect("regex")),
            ("scope-change", Regex::new(r"\b(?:widen|expand)\b(?:\s+[a-z0-9]+){0,2}\s+scope\b").expect("regex")),
            ("freeze", Regex::new(r"\b(?:unfreeze|lift)\b(?:\s+[a-z0-9]+){0,2}\s+(?:freeze|spec)\b").expect("regex")),
            ("spend", Regex::new(r"\b(?:buy|purchase|upgrade|increase|enable|raise|charge)\b(?:\s+[a-z0-9]+){1,3}\s+(?:license|plan|quota|billing|spending\s+limit|card)\b").expect("regex")),
        ]
    })
}

fn door_raw_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            ("merge-to-default", Regex::new(r"\bgit\s+push\b[^\n;]{0,50}(?:--force(?:-with-lease)?|(?:^|\s)-[a-z]*f[a-z]*\b)[^\n;]{0,40}\b(?:main|master)\b").expect("regex")),
            ("merge-to-default", Regex::new(r"\bgit\s+push\b[^\n;]{0,40}\b(?:main|master)\b[^\n;]{0,40}(?:--force(?:-with-lease)?|(?:^|\s)-[a-z]*f[a-z]*\b)").expect("regex")),
            ("deletion", Regex::new(r"\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\b").expect("regex")),
            ("deletion", Regex::new(r"\bgit\s+branch\b[^\n;]{0,40}(?:(?:^|\s)-d\s+-f|(?:^|\s)-f\s+-d|--delete\s+--force|--force\s+--delete)\b").expect("regex")),
            ("deletion", Regex::new(r"\bgit\s+push\b[^\n;]{0,40}(?:--delete[^\n;]{0,20}\b(?:main|master)\b|:(?:main|master)\b)").expect("regex")),
        ]
    })
}

fn door_case_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![(
            "deletion",
            Regex::new(r"\bgit\s+branch\b[^\n;]{0,40}(?:^|\s)-D\b").expect("regex"),
        )]
    })
}

pub fn door_hits(text: &str, net: &[(String, String)]) -> Vec<String> {
    if net.is_empty() {
        return Vec::new();
    }
    let probe = fold(text);
    let norm = normalize_text(text);
    let raw = norm.to_lowercase();
    let mut hits: BTreeSet<String> = BTreeSet::new();
    let mut net_doors: BTreeSet<&str> = BTreeSet::new();
    for (door_id, kw) in net {
        net_doors.insert(door_id.as_str());
        if probe.contains(kw.as_str()) {
            hits.insert(door_id.clone());
        }
    }
    for (door_id, pat) in door_folded_patterns() {
        if net_doors.contains(door_id) && pat.is_match(&probe) {
            hits.insert((*door_id).to_string());
        }
    }
    for (door_id, pat) in door_raw_patterns() {
        if net_doors.contains(door_id) && pat.is_match(&raw) {
            hits.insert((*door_id).to_string());
        }
    }
    for (door_id, pat) in door_case_patterns() {
        if net_doors.contains(door_id) && pat.is_match(&norm) {
            hits.insert((*door_id).to_string());
        }
    }
    hits.into_iter().collect()
}

fn find_default_doors() -> Option<PathBuf> {
    if let Ok(root) = env::var("OPEN_FLEET_ROOT") {
        let p = PathBuf::from(root).join("runtime/one-way-doors.json");
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(cwd) = env::current_dir() {
        let mut cur: Option<&Path> = Some(cwd.as_path());
        while let Some(d) = cur {
            let p = d.join("runtime/one-way-doors.json");
            if p.is_file() {
                return Some(p);
            }
            cur = d.parent();
        }
    }
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent();
        while let Some(d) = cur {
            let p = d.join("runtime/one-way-doors.json");
            if p.is_file() {
                return Some(p);
            }
            cur = d.parent();
        }
    }
    None
}

pub fn load_doors(explicit: Option<&Path>) -> Result<Vec<(String, String)>, String> {
    let p = match explicit {
        Some(path) => path.to_path_buf(),
        None => find_default_doors().ok_or_else(|| {
            "one-way door registry runtime/one-way-doors.json is unusable: not found".to_string()
        })?,
    };
    let text = fs::read_to_string(&p)
        .map_err(|err| format!("one-way door registry {} is unusable: {err}", p.display()))?;
    let data: Value = serde_json::from_str(&text)
        .map_err(|err| format!("one-way door registry {} is unusable: {err}", p.display()))?;
    let Some(doors) = data.get("doors").and_then(|v| v.as_array()) else {
        return Err(format!(
            "one-way door registry {} declares no doors",
            p.display()
        ));
    };
    if doors.is_empty() {
        return Err(format!(
            "one-way door registry {} declares no doors",
            p.display()
        ));
    }
    let mut net = Vec::new();
    for door in doors {
        let did = door.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let keywords = door.get("keywords").and_then(|v| v.as_array());
        if did.is_empty() || keywords.map(|k| k.is_empty()).unwrap_or(true) {
            return Err(format!(
                "one-way door registry {}: door {:?} has no keyword net",
                p.display(),
                did
            ));
        }
        for kw in keywords.expect("checked") {
            let s = match kw {
                Value::String(st) => st.clone(),
                other => other.to_string(),
            };
            net.push((did.to_string(), fold(&s)));
        }
    }
    Ok(net)
}

pub fn default_decisions_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    for var in [PRIMARY_DECISIONS_ENV, DECISIONS_ENV] {
        if let Ok(v) = env::var(var) {
            if !v.trim().is_empty() {
                return PathBuf::from(v.trim());
            }
        }
    }
    PathBuf::from(DEFAULT_LOG)
}

fn abspath(p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    };
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    stack.pop();
                } else if !matches!(
                    stack.last(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    stack.push(comp);
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = PathBuf::new();
    for c in stack {
        out.push(c.as_os_str());
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn realpath_best_effort(p: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(p) {
        return c;
    }
    let abs = abspath(p);
    let mut cur = abs.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            tail.push(name.to_os_string());
        }
        if let Ok(canon) = fs::canonicalize(parent) {
            let mut out = canon;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        cur = parent;
    }
    abs
}

fn read_gitfile_text(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
        if !ok || (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe { libc::close(fd) };
            return None;
        }
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        unsafe { libc::close(fd) };
        if n < 0 {
            return None;
        }
        String::from_utf8(buf[..n as usize].to_vec())
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(unix))]
    {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }
}

fn linked_worktree_of(inner: &Path, outer: &Path) -> bool {
    let gitfile = inner.join(".git");
    let admin = outer.join(".git").join("worktrees");
    if fs::symlink_metadata(outer.join(".git"))
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return false;
    }
    let Some(text) = read_gitfile_text(&gitfile) else {
        return false;
    };
    let Some(rest) = text.strip_prefix("gitdir:") else {
        return false;
    };
    let raw_target = PathBuf::from(rest.trim());
    let target = realpath_best_effort(&if raw_target.is_absolute() {
        raw_target
    } else {
        inner.join(raw_target)
    });
    if target.parent() != Some(realpath_best_effort(&admin).as_path()) || !target.is_dir() {
        return false;
    }
    let Some(back) = read_gitfile_text(&target.join("gitdir")) else {
        return false;
    };
    let back_p = PathBuf::from(&back);
    let back_resolved = realpath_best_effort(&if back_p.is_absolute() {
        back_p
    } else {
        target.join(back_p)
    });
    back_resolved == realpath_best_effort(&gitfile)
}

fn repo_for_path(target_path: &Path) -> Result<PathBuf, String> {
    let lexical = abspath(target_path);
    let real = realpath_best_effort(&lexical);
    let mut found: Vec<PathBuf> = Vec::new();
    for start in [real.as_path(), lexical.as_path()] {
        let mut cur = start.parent();
        while let Some(cand) = cur {
            if fs::symlink_metadata(cand.join(".git")).is_ok() {
                let rp = realpath_best_effort(cand);
                if !found.contains(&rp) {
                    found.push(rp);
                }
            }
            cur = cand.parent();
        }
    }
    if found.is_empty() {
        return Ok(env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    }
    if found.len() == 1 {
        return Ok(found[0].clone());
    }
    if found.len() == 2 && linked_worktree_of(&found[0], &found[1]) {
        return Ok(found[0].clone());
    }
    Err(format!(
        "the nearest repository root {} is nested inside the repository {} (a submodule, vendored repository or planted .git): refusing to resolve the human-grant trust anchor in a nested repository (C20)",
        found[0].display(),
        found[found.len() - 1].display()
    ))
}

fn run_hardened_git(root: &Path, args: &[&str]) -> Result<(i32, Vec<u8>), String> {
    let out = gitexec::run_git_repo(root, args, &[])?;
    Ok((out.code, out.stdout))
}

fn pin_at_ref(root: &Path, reference: &str) -> Result<Option<[u8; 32]>, String> {
    if reference.is_empty() || reference.starts_with('-') {
        return Err(format!(
            "--pin-ref {reference:?} must name a git ref, not an option"
        ));
    }
    let commit = match gitexec::remote_tracking_commit(root, reference) {
        Ok((c, _target)) => c,
        Err((_, why)) => {
            return Err(format!(
                "--pin-ref {reference:?} {why} — it does not resolve to a commit under the exact-name anchor rule in {}, so it anchors nothing (W3-07)",
                root.display()
            ));
        }
    };
    let (lc, lout) = run_hardened_git(
        root,
        &[
            "ls-tree",
            "--name-only",
            "--full-tree",
            &commit,
            "--",
            GRANT_PUBKEY_REL,
        ],
    )?;
    if lc != 0 {
        return Err(format!(
            "cannot list {GRANT_PUBKEY_REL} at {reference} ({})",
            &commit[..12.min(commit.len())]
        ));
    }
    let listed = String::from_utf8_lossy(&lout);
    if !listed.lines().any(|ln| ln == GRANT_PUBKEY_REL) {
        return Ok(None);
    }
    let spec = format!("{commit}:{GRANT_PUBKEY_REL}");
    let (bc, bout) = run_hardened_git(root, &["cat-file", "blob", &spec])?;
    if bc != 0 {
        return Err(format!(
            "{reference}:{GRANT_PUBKEY_REL} is pinned but its blob is unreadable here"
        ));
    }
    let text = String::from_utf8_lossy(&bout);
    let pub_key = parse_grant_pubkey(&text, &format!("{reference}:{GRANT_PUBKEY_REL}"))?;
    Ok(Some(pub_key))
}

pub fn grant_pubkey(log_path: &Path, pin_ref: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    if pin_ref.is_none() {
        if let Some(lane) = gitexec::sound_lane() {
            return Err(format!(
                "{lane} claims a sound lane, but no --pin-ref names the trust anchor: the human-grant key would come from the working tree the checked change writes (a swapped or deleted pin included). Pass --pin-ref refs/remotes/origin/<default> or a commit id (W3-07, #635)"
            ));
        }
    }
    let root = repo_for_path(log_path)?;
    let pin = root.join(GRANT_PUBKEY_REL);
    let tree = if pin.exists() {
        let text = fs::read_to_string(&pin)
            .map_err(|err| format!("{} is unreadable: {err}", pin.display()))?;
        Some(parse_grant_pubkey(&text, &pin.display().to_string())?)
    } else {
        None
    };
    let Some(pref) = pin_ref else {
        let said = if tree.is_some() {
            format!(
                "the human-grant key was read from the working tree ({})",
                pin.display()
            )
        } else {
            format!(
                "no human-grant key is pinned in the working tree ({} is absent), so one-way grants are checked unsigned",
                pin.display()
            )
        };
        eprintln!(
            "decisions.py: NOTE — {said}; a change under check can swap or delete that pin. Pass --pin-ref refs/remotes/origin/<default> (or a commit id) to anchor it (W3-07, #635)"
        );
        return Ok(tree);
    };
    let trusted = pin_at_ref(&root, pref)?;
    if tree != trusted {
        return Err(format!(
            "the working tree's {GRANT_PUBKEY_REL} differs from the one pinned at {pref} — a pin the checked tree swapped in is not a trust anchor (--pin-ref)"
        ));
    }
    Ok(trusted)
}

pub fn read_lines(path: &Path) -> Result<Vec<(usize, DecisionRecord)>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("{} is unreadable: {err}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        if let Some(rec) = parse_line(line) {
            out.push((i + 1, rec));
        }
    }
    Ok(out)
}

fn validate_with_doors(
    record: &DecisionRecord,
    net: &[(String, String)],
    grant_pub: Option<&[u8; 32]>,
) -> Vec<String> {
    let mut problems = validate_record(record, grant_pub);
    let hits = door_hits(&record.raw, net);
    if !hits.is_empty() && record.class != "one-way" {
        problems.push(format!(
            "matches the one-way net ({}) but is classed {:?} — one-way doors are human-only and are never auto-resolved",
            hits.join(", "),
            record.class
        ));
    }
    problems
}

fn is_standing_malformed(r: &DecisionRecord) -> bool {
    if r.id.is_empty() || r.answer.is_empty() || r.why.is_empty() {
        return true;
    }
    if !CLASSES.contains(&r.class.as_str()) {
        return true;
    }
    let Some(inst) = instant(&r.ts) else {
        return true;
    };
    if (inst - Utc::now()).num_seconds() > MAX_FUTURE_SKEW_SECONDS {
        return true;
    }
    if has_invisible_cf(&r.raw)
        || has_invisible_cf(&r.ts)
        || has_invisible_cf(&r.id)
        || has_invisible_cf(&r.class)
        || has_invisible_cf(&r.answer)
        || has_invisible_cf(&r.why)
        || has_invisible_cf(&r.task_id)
    {
        return true;
    }
    if has_line_break(&r.raw)
        || has_line_break(&r.ts)
        || has_line_break(&r.id)
        || has_line_break(&r.class)
        || has_line_break(&r.answer)
        || has_line_break(&r.why)
        || has_line_break(&r.task_id)
    {
        return true;
    }
    if r.class != "one-way" {
        if let Some(caps) = human_source_suffix_re().captures(&r.why) {
            if caps.get(2).is_some() {
                return true;
            }
        }
    }
    false
}

fn is_waiver_retirement(record: &DecisionRecord, prior_ow: &DecisionRecord) -> bool {
    record.id.trim().starts_with("floor-waiver:")
        && record.answer.trim().eq_ignore_ascii_case("superseded")
        && prior_ow.answer.trim().eq_ignore_ascii_case("allow")
}

fn valid_one_way(record: &DecisionRecord, grant_pub: Option<&[u8; 32]>) -> bool {
    record.class == "one-way" && grant_problems(record, grant_pub).is_empty()
}

fn format_line(
    ts: &str,
    ident: &str,
    klass: &str,
    answer: &str,
    why: &str,
    task_id: Option<&str>,
) -> String {
    let mut fields = vec![ts, ident, klass, answer, why];
    if let Some(t) = task_id {
        if !t.is_empty() {
            fields.push(t);
        }
    }
    fields.join(" · ")
}

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if s == "~" {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    path.to_path_buf()
}

fn seed_in_unignored_worktree(path: &Path) -> bool {
    let abs = abspath(path);
    let real = realpath_best_effort(&abs);
    let mut roots: Vec<PathBuf> = Vec::new();
    for start in [real.as_path(), abs.as_path()] {
        let mut cur = start.parent();
        while let Some(cand) = cur {
            if fs::symlink_metadata(cand.join(".git")).is_ok() {
                let rp = realpath_best_effort(cand);
                if !roots.contains(&rp) {
                    roots.push(rp);
                }
            }
            cur = cand.parent();
        }
    }
    // Also check git rev-parse --show-toplevel on nearest existing parent
    let mut probe = abs.parent();
    while let Some(d) = probe {
        if d.is_dir() {
            if let Ok(out) = Command::new("git")
                .args(["-C", &d.to_string_lossy(), "rev-parse", "--show-toplevel"])
                .stdin(Stdio::null())
                .output()
            {
                if out.status.success() {
                    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !top.is_empty() {
                        let rp = realpath_best_effort(Path::new(&top));
                        if !roots.contains(&rp) {
                            roots.push(rp);
                        }
                    }
                }
            }
            break;
        }
        probe = d.parent();
    }
    if roots.is_empty() {
        return false;
    }
    for root in roots {
        let rel = real
            .strip_prefix(&root)
            .or_else(|_| abs.strip_prefix(&root));
        let Ok(rel_path) = rel else {
            continue;
        };
        let status = Command::new("git")
            .args([
                "-C",
                &root.to_string_lossy(),
                "check-ignore",
                "-q",
                "--",
                &rel_path.to_string_lossy(),
            ])
            .stdin(Stdio::null())
            .status();
        match status {
            Ok(st) if st.code() == Some(0) => continue,
            _ => return true, // unignored (1) or failed check (fail closed)
        }
    }
    false
}

pub struct AppendArgs {
    pub file: PathBuf,
    pub doors: Option<PathBuf>,
    pub pin_ref: Option<String>,
    pub id: String,
    pub klass: String,
    pub answer: String,
    pub why: String,
    pub task: Option<String>,
    pub source: Option<String>,
    pub grant_sig: Option<String>,
    pub ts: Option<String>,
}

pub fn cmd_append(args: &AppendArgs) -> i32 {
    if !CLASSES.contains(&args.klass.as_str()) {
        eprintln!(
            "decisions: invalid --class {:?} (expected one of: mechanical, taste, one-way)",
            args.klass
        );
        return EXIT_CANNOT_RUN;
    }
    let net = match load_doors(args.doors.as_deref()) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let pub_key = match grant_pubkey(&args.file, args.pin_ref.as_deref()) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let ts = args
        .ts
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let mut why = args.why.clone();

    if args.grant_sig.is_some() && args.klass != "one-way" {
        eprintln!(
            "decisions: --grant-sig binds a one-way human grant; it has no meaning on a {} line",
            args.klass
        );
        return EXIT_VIOLATION;
    }
    if args.klass == "one-way" && args.source.is_none() {
        eprintln!("decisions: class one-way with no human source — requires --source human:<name>, passed by the coordinator who received the grant — a source marker typed into --why is prose any worker can write, not a source");
        return EXIT_VIOLATION;
    }
    if args.grant_sig.is_some() && pub_key.is_none() {
        eprintln!("decisions: --grant-sig given but no human grant pubkey is pinned (.orca/human-grant-pubkey) — refusing a signature nothing can verify");
        return EXIT_VIOLATION;
    }
    if let Some(src) = args.source.as_deref() {
        let name = src.strip_prefix("human:").unwrap_or("");
        if !src.starts_with("human:")
            || name.contains(char::is_whitespace)
            || !human_name_re().is_match(name)
            || RESERVED_HUMAN_NAMES.contains(&name.to_ascii_lowercase().as_str())
        {
            eprintln!("decisions: --source must be shaped human:<name> and name a person, not an agent role");
            return EXIT_VIOLATION;
        }
        let mut effective_sig = args.grant_sig.clone();
        if let Some(caps) = human_source_suffix_re().captures(&why) {
            let emb_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let emb_sig = caps.get(2).map(|m| m.as_str().to_string());
            if emb_name != name
                || (emb_sig.is_some()
                    && effective_sig.is_some()
                    && !emb_sig
                        .as_deref()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(effective_sig.as_deref().unwrap_or("")))
            {
                eprintln!("decisions: --why carries a source marker that does not match --source; refusing a smuggled or mismatched source");
                return EXIT_VIOLATION;
            }
            if effective_sig.is_none() {
                effective_sig = emb_sig;
            }
            let start = caps.get(0).map(|m| m.start()).unwrap_or(why.len());
            why = why[..start].trim_end().to_string();
        } else if why.contains("source=") {
            eprintln!("decisions: --why carries a source marker that does not match --source; refusing a smuggled or mismatched source");
            return EXIT_VIOLATION;
        }
        if effective_sig.is_some() && args.klass != "one-way" {
            eprintln!(
                "decisions: a grant signature embedded in --why binds a one-way grant; it has no meaning on a {} line",
                args.klass
            );
            return EXIT_VIOLATION;
        }
        if args.klass == "one-way" && pub_key.is_some() && effective_sig.is_none() {
            eprintln!("decisions: a human grant pubkey is pinned, so a one-way append requires --grant-sig from the human's key (`sign-grant`)");
            return EXIT_VIOLATION;
        }
        if effective_sig.is_some() && args.ts.is_none() {
            eprintln!("decisions: a grant signature binds the line's timestamp — pass the --ts that sign-grant printed");
            return EXIT_VIOLATION;
        }
        if let Some(sig) = effective_sig {
            if !sig128_re().is_match(&sig) {
                eprintln!("decisions: --grant-sig must be 128 hex characters");
                return EXIT_VIOLATION;
            }
            why = format!("{why} [source={src} sig={}]", sig.to_ascii_lowercase());
        } else {
            why = format!("{why} [source={src}]");
        }
    }

    let task_val = args.task.as_deref().unwrap_or("");
    for (fname, val) in [
        ("ts", ts.as_str()),
        ("id", args.id.as_str()),
        ("answer", args.answer.as_str()),
        ("why", why.as_str()),
        ("task", task_val),
    ] {
        if val.contains(SEP_CHAR) || has_line_break(val) {
            eprintln!(
                "decisions: {fname} may not contain '{SEP_CHAR}' or a line break (one record, one line)"
            );
            return EXIT_VIOLATION;
        }
    }

    let line = format_line(
        &ts,
        args.id.trim(),
        &args.klass,
        args.answer.trim(),
        why.trim(),
        Some(task_val.trim()),
    );
    let Some(record) = parse_line(&line) else {
        eprintln!("decisions: refusing to write an unparseable line");
        return EXIT_VIOLATION;
    };

    let mut problems = validate_with_doors(&record, &net, pub_key.as_ref());
    if record.class != "one-way" {
        let existing = match read_lines(&args.file) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("decisions: could not run: {err}");
                return EXIT_CANNOT_RUN;
            }
        };
        let mut prior_ow: Vec<((DateTime<Utc>, usize), DecisionRecord)> = existing
            .into_iter()
            .enumerate()
            .filter(|(_, (_, r))| {
                r.id == record.id && !is_standing_malformed(r) && valid_one_way(r, pub_key.as_ref())
            })
            .map(|(i, (_, r))| (recency(&r, i), r))
            .collect();
        prior_ow.sort_by_key(|(k, _)| *k);
        if let Some((_, last_ow)) = prior_ow.last() {
            if !is_waiver_retirement(&record, last_ow) {
                problems.push(format!(
                    "class monotonicity: id {:?} already has a standing one-way decision and cannot be downgraded to {:?} (#772)",
                    record.id, record.class
                ));
            }
        }
    }

    if !problems.is_empty() {
        eprintln!("decisions: refused:");
        for p in problems {
            eprintln!("  - {p}");
        }
        return EXIT_VIOLATION;
    }

    if let Some(parent) = args.file.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!(
                    "decisions: could not run: {} could not be appended: {err}",
                    args.file.display()
                );
                return EXIT_CANNOT_RUN;
            }
        }
    }
    let exists = args.file.exists();
    let write_res = (|| -> Result<(), std::io::Error> {
        let mut fh = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.file)?;
        if !exists {
            fh.write_all(
                b"# DECISIONS\n\n`ts \xc2\xb7 gate-or-ask-id \xc2\xb7 class \xc2\xb7 answer \xc2\xb7 why \xc2\xb7 task_id?`\n\n",
            )?;
        }
        fh.write_all(line.as_bytes())?;
        fh.write_all(b"\n")?;
        Ok(())
    })();
    if let Err(err) = write_res {
        eprintln!(
            "decisions: could not run: {} could not be appended: {err}",
            args.file.display()
        );
        return EXIT_CANNOT_RUN;
    }
    println!("{line}");
    EXIT_OK
}

pub fn cmd_active(file: &Path, pin_ref: Option<&str>, json_out: bool) -> i32 {
    let records_with_no = match read_lines(file) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let pub_key = match grant_pubkey(file, pin_ref) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let records: Vec<DecisionRecord> = records_with_no.into_iter().map(|(_, r)| r).collect();
    let stood = standing(&records, pub_key.as_ref());
    let rows = active(&stood);
    if json_out {
        let items: Vec<Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "ts": r.ts,
                    "id": r.id,
                    "class": r.class,
                    "answer": r.answer,
                    "why": r.why,
                    "task_id": r.task_id,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        for r in rows {
            println!("{}", r.raw);
        }
    }
    EXIT_OK
}

pub fn cmd_tally(file: &Path, lens: &str, json_out: bool) -> i32 {
    let records_with_no = match read_lines(file) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let ident = format!("lens-tally:{lens}");
    let mut rows: Vec<((DateTime<Utc>, usize), DecisionRecord)> = records_with_no
        .into_iter()
        .enumerate()
        .filter(|(_, (_, r))| r.id == ident)
        .map(|(i, (_, r))| (recency(&r, i), r))
        .collect();
    rows.sort_by_key(|(k, _)| *k);

    let mut streak = 0usize;
    for (_, r) in rows.iter().rev() {
        if zero_only_re().is_match(r.answer.trim()) {
            streak += 1;
        } else {
            break;
        }
    }
    let never = NEVER_GATE.contains(&lens);
    let may_gate_off = !never && streak >= GATE_OFF_STREAK;
    if json_out {
        let obj = serde_json::json!({
            "lens": lens,
            "dispatches": rows.len(),
            "zero_streak": streak,
            "never_gate": never,
            "may_gate_off": may_gate_off,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        let gate = if may_gate_off {
            "may auto-gate off"
        } else if never {
            "NEVER_GATE"
        } else {
            "stays on"
        };
        println!(
            "lens={lens} dispatches={} zero_streak={streak} → {gate}",
            rows.len()
        );
    }
    EXIT_OK
}

fn base_record_counts(log_path: &Path, base_ref: &str) -> Result<HashMap<String, usize>, String> {
    if base_ref.is_empty() || base_ref.starts_with('-') {
        return Err(format!(
            "--base {base_ref:?} must name a git ref, not an option"
        ));
    }
    let root = repo_for_path(log_path)?;
    let real = realpath_best_effort(&abspath(log_path));
    let rel_path = real.strip_prefix(&root).map_err(|_| {
        format!(
            "--base requires {} to sit inside repository {}",
            log_path.display(),
            root.display()
        )
    })?;
    let rel = rel_path.to_string_lossy().replace('\\', "/");

    let resolved = gitexec::base_commit(&root, Some(base_ref)).map_err(|why| {
        format!(
            "--base {base_ref:?} {why} — cannot read base ledger in {}",
            root.display()
        )
    })?;
    let commit = resolved.commit;
    let shown = resolved.shown;
    if let Some(local_kind) = resolved.local {
        if let Some(lane) = gitexec::sound_lane() {
            return Err(format!(
                "{lane} claims a sound lane, but --base {shown:?} is {local_kind} ({}), not a remote-tracking ref or full commit id",
                &commit[..12.min(commit.len())]
            ));
        }
    }
    let (lc, lout) = run_hardened_git(
        &root,
        &["ls-tree", "--name-only", "--full-tree", &commit, "--", &rel],
    )?;
    if lc != 0 {
        return Err(format!(
            "cannot list {rel} at --base {base_ref} ({})",
            &commit[..12.min(commit.len())]
        ));
    }
    if !String::from_utf8_lossy(&lout).lines().any(|ln| ln == rel) {
        return Ok(HashMap::new());
    }
    let spec = format!("{commit}:{rel}");
    let (bc, bout) = run_hardened_git(&root, &["cat-file", "blob", &spec])?;
    if bc != 0 {
        return Err(format!("{base_ref}:{rel} is listed but unreadable"));
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for line in String::from_utf8_lossy(&bout).lines() {
        if let Some(rec) = parse_line(line) {
            *counts.entry(rec.raw).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

pub struct CheckArgs {
    pub file: PathBuf,
    pub doors: Option<PathBuf>,
    pub pin_ref: Option<String>,
    pub since: Option<String>,
    pub base: Option<String>,
}

pub fn cmd_check(args: &CheckArgs) -> i32 {
    let net = match load_doors(args.doors.as_deref()) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let pub_key = match grant_pubkey(&args.file, args.pin_ref.as_deref()) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let records = match read_lines(&args.file) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("decisions: could not run: {err}");
            return EXIT_CANNOT_RUN;
        }
    };
    let fence = if let Some(since) = args.since.as_deref() {
        if !since_date_re().is_match(since) {
            eprintln!("decisions: --since {since:?} is not a date (YYYY-MM-DD)");
            return EXIT_CANNOT_RUN;
        }
        let stamp = format!("{since}T00:00:00Z");
        match instant(&stamp) {
            Some(dt) => Some(dt),
            None => {
                eprintln!("decisions: --since {since:?} is not a valid calendar date");
                return EXIT_CANNOT_RUN;
            }
        }
    } else {
        None
    };
    let mut base_counts = if let Some(bref) = args.base.as_deref() {
        match base_record_counts(&args.file, bref) {
            Ok(c) => Some(c),
            Err(err) => {
                eprintln!("decisions: could not run: {err}");
                return EXIT_CANNOT_RUN;
            }
        }
    } else {
        None
    };

    let mut checked: Vec<(usize, usize, &DecisionRecord)> = Vec::new();
    let mut legacy = 0usize;
    for (pos, (lineno, rec)) in records.iter().enumerate() {
        let inst = instant(&rec.ts);
        let mut untouched = false;
        if let Some(ref mut counts) = base_counts {
            if let Some(c) = counts.get_mut(&rec.raw) {
                if *c > 0 {
                    *c -= 1;
                    untouched = true;
                }
            }
        }
        let may_skip = if base_counts.is_some() {
            untouched
        } else {
            true
        };
        if may_skip {
            if let (Some(f), Some(i)) = (fence, inst) {
                if i < f {
                    legacy += 1;
                    continue;
                }
            }
        }
        checked.push((pos, *lineno, rec));
    }

    type OwEntry<'a> = ((DateTime<Utc>, usize), usize, &'a DecisionRecord);
    let mut ow_by_id: HashMap<&str, Vec<OwEntry<'_>>> = HashMap::new();
    for (pos, (_, rec)) in records.iter().enumerate() {
        if !is_standing_malformed(rec) && valid_one_way(rec, pub_key.as_ref()) {
            ow_by_id
                .entry(rec.id.as_str())
                .or_default()
                .push((recency(rec, pos), pos, rec));
        }
    }
    for rows in ow_by_id.values_mut() {
        rows.sort_by_key(|(k, _, _)| *k);
    }

    let mut failures = Vec::new();
    for (pos, lineno, rec) in &checked {
        for prob in validate_with_doors(rec, &net, pub_key.as_ref()) {
            failures.push(format!("{}:{lineno}: {prob}", args.file.display()));
        }
        if rec.class != "one-way" {
            let rec_key = recency(rec, *pos);
            let prior_ow: Vec<&OwEntry<'_>> = ow_by_id
                .get(rec.id.as_str())
                .map(|rows| {
                    rows.iter()
                        .filter(|(k, p, _)| *k < rec_key || *p < *pos)
                        .collect()
                })
                .unwrap_or_default();
            if let Some((_, _, last_ow)) = prior_ow.last() {
                if !is_waiver_retirement(rec, last_ow) {
                    failures.push(format!(
                        "{}:{lineno}: class monotonicity: id {:?} already has a standing one-way decision and cannot be downgraded to {:?} (#772)",
                        args.file.display(),
                        rec.id,
                        rec.class
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        for f in failures {
            eprintln!("{f}");
        }
        return EXIT_VIOLATION;
    }
    let tail = if let Some(since) = args.since.as_deref() {
        format!(" ({legacy} earlier record(s) before {since} not re-checked)")
    } else {
        String::new()
    };
    println!(
        "decisions: {} record(s) valid in {}{tail}",
        checked.len(),
        args.file.display()
    );
    EXIT_OK
}

pub fn cmd_grant_keygen(out_raw: &Path, in_repo_ok: bool) -> i32 {
    let out = expand_tilde(out_raw);
    let pub_path = PathBuf::from(format!("{}.pub", out.display()));
    if seed_in_unignored_worktree(&out) && !in_repo_ok {
        eprintln!("decisions: grant-keygen refuses to write a human seed inside a git work tree that does not ignore it (it is a private key — one `git add -A` would publish it; keep it with your other keys, e.g. ~/.open-fleet/human-grant-key; --in-repo-ok overrides)");
        return EXIT_VIOLATION;
    }
    if out.exists() || pub_path.exists() {
        eprintln!(
            "decisions: refusing to overwrite {} or {}",
            out.display(),
            pub_path.display()
        );
        return EXIT_VIOLATION;
    }
    let mut seed = [0u8; 32];
    if let Err(err) = getrandom::getrandom(&mut seed) {
        eprintln!("decisions: could not run: random seed generation failed: {err}");
        return EXIT_CANNOT_RUN;
    }
    let signing = SigningKey::from_bytes(&seed);
    let pub_hex = hex::encode(signing.verifying_key().to_bytes());
    let seed_hex = hex::encode(seed);

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!("decisions: could not run: grant key could not be written: {err}");
                return EXIT_CANNOT_RUN;
            }
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write_res = opts
        .open(&out)
        .and_then(|mut f| f.write_all(format!("{seed_hex}\n").as_bytes()))
        .and_then(|_| fs::write(&pub_path, format!("{pub_hex}\n")));
    if let Err(err) = write_res {
        eprintln!("decisions: could not run: grant key could not be written: {err}");
        return EXIT_CANNOT_RUN;
    }
    println!("{pub_hex}");
    eprintln!(
        "decisions: seed at {} (never commit it, never give it to a worker); commit {} as .orca/human-grant-pubkey to turn signed grants on",
        out.display(),
        pub_path.display()
    );
    EXIT_OK
}

pub struct SignGrantArgs {
    pub key: PathBuf,
    pub id: String,
    pub answer: String,
    pub why: String,
    pub task: Option<String>,
    pub source: Option<String>,
    pub ts: Option<String>,
}

pub fn cmd_sign_grant(args: &SignGrantArgs) -> i32 {
    let key_path = expand_tilde(&args.key);
    let meta = match fs::metadata(&key_path) {
        Ok(m) => m,
        Err(err) => {
            eprintln!(
                "decisions: could not run: grant key {} is not a readable hex seed: {err}",
                args.key.display()
            );
            return EXIT_CANNOT_RUN;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            eprintln!(
                "decisions: seed custody: {} is mode {:04o} — readable beyond its owner; refusing (chmod 0600, or grant-keygen anew)",
                key_path.display(),
                mode
            );
            return EXIT_VIOLATION;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
    }
    if seed_in_unignored_worktree(&key_path) {
        eprintln!(
            "decisions: seed custody: {} is inside a git work tree that does not ignore it — one `git add -A` would commit the private seed; refusing",
            key_path.display()
        );
        return EXIT_VIOLATION;
    }
    let raw_seed = match fs::read_to_string(&key_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "decisions: could not run: grant key {} is not a readable hex seed: {err}",
                args.key.display()
            );
            return EXIT_CANNOT_RUN;
        }
    };
    let seed_vec = match hex::decode(raw_seed.trim()) {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "decisions: could not run: grant key {} is not a readable hex seed: {err}",
                args.key.display()
            );
            return EXIT_CANNOT_RUN;
        }
    };
    let seed_arr: [u8; 32] = match seed_vec.try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!(
                "decisions: could not run: grant key {} is not a 32-byte seed",
                args.key.display()
            );
            return EXIT_CANNOT_RUN;
        }
    };

    let mut why = args.why.clone();
    if let Some(caps) = human_source_suffix_re().captures(&why) {
        let start = caps.get(0).map(|m| m.start()).unwrap_or(why.len());
        why = why[..start].trim_end().to_string();
    }
    let ts = args
        .ts
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let Some(inst) = instant(&ts) else {
        eprintln!("decisions: --ts {ts:?} is not an ISO timestamp");
        return EXIT_VIOLATION;
    };
    if !ts_prefix_re().is_match(&ts) {
        eprintln!("decisions: --ts {ts:?} is not an ISO timestamp");
        return EXIT_VIOLATION;
    }
    if (inst - Utc::now()).num_seconds() > MAX_FUTURE_SKEW_SECONDS {
        eprintln!("decisions: refusing to sign a grant stamped in the future — it would out-rank every later decision on this id (P2-3)");
        return EXIT_VIOLATION;
    }
    if let Some(src) = args.source.as_deref() {
        let name = src.strip_prefix("human:").unwrap_or("");
        if !src.starts_with("human:")
            || name.contains(char::is_whitespace)
            || !human_name_re().is_match(name)
            || RESERVED_HUMAN_NAMES.contains(&name.to_ascii_lowercase().as_str())
        {
            eprintln!("decisions: --source must be shaped human:<name> and name a person, not an agent role");
            return EXIT_VIOLATION;
        }
    }

    let payload = grant_payload(
        args.id.trim(),
        args.answer.trim(),
        why.trim(),
        args.task.as_deref().unwrap_or("").trim(),
        &ts,
        "one-way",
        args.source.as_deref(),
    );
    let signing = SigningKey::from_bytes(&seed_arr);
    let sig = signing.sign(&payload);
    println!("{}", hex::encode(sig.to_bytes()));
    eprintln!("decisions: signed for ts={ts} — append this grant with --ts {ts}");
    EXIT_OK
}
