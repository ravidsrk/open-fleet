//! Native Rust port of `runtime/scripts/run_report.py`:
//! bind proof-tier advances to SHA-pinned run artifacts, command ledgers,
//! Ed25519-signed verifier transcripts, Ed25519-signed integrity inventories,
//! and WIP-curve protocol rows (#259, #281, #286, #365, #386, #389, #784).

use crate::base64_codec::decode_strict;
use crate::dispatch_sign::{canonical_record, verify_bytes, TRANSCRIPT_FIELDS};
use crate::inventory::{
    check_entries, find_signature, inventory_digest, load_report, repo_root, rev_exists,
    verify_signature, InventoryEntry, SIGNATURE_TAG,
};
use crate::proof_status::collect as collect_proof_status;
use of_common::gitexec::{remote_tracking_commit, run_git_repo, sound_lane as gitexec_sound_lane};
use of_common::wip_rows::{split_python_lines, wip_rows, WIP_ROW_KEYS, WIP_SECTION};
use of_install::find_catalog_root;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

pub const PUBKEY_PIN: &str = ".orca/dispatch-pubkey";
pub const REQUIRED_FIELDS: &[&str] = &["mission", "tier", "inventory_at", "manifest", "verifier"];
pub const VERIFIER_OUTCOMES: &[&str] = &["GREEN", "RED"];
pub const TIERS: &[&str] = &["doctrine-only", "self-run", "external-run"];
pub const ADVANCING_TIERS: &[&str] = &["self-run", "external-run"];
pub const SHALLOW_REMEDY: &str = "git fetch --unshallow";
pub const VERIFIER_PATH_PARTS: &[&str] = &["runtime", "scripts", "verify.py"];
pub const EMPTY_TREES: &[&str] = &[
    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
];
pub const SIGNED_ARGS: &[&str] = &[
    "contract_source",
    "contract_digest",
    "repo",
    "base",
    "symbol",
    "execute_nc",
    "allow_static_nc",
    "unit_class",
    "no_gh",
    "lighting",
    "lane",
    "dispatch_record",
    "dispatch_pubkey",
    "nc_command",
    "git_dir",
    "evidence_root",
    "provenance",
    "retention_pubkey",
];
const SWITCH_ARGS: &[&str] = &["execute_nc", "allow_static_nc", "no_gh"];
pub const TOOLCHAIN_FILES: &[&str] = &[
    "verify.py",
    "_verify_sig.py",
    "_verify_diff.py",
    "diff_scope.py",
    "ed25519.py",
    "dispatch-sign.py",
    "inventory.py",
    "gitexec.py",
];
pub const GRADING_BASES: &[&str] = &[
    "origin/HEAD",
    "origin/main",
    "origin/master",
    "main",
    "master",
    "HEAD",
];
pub const PROVENANCE_VARS: &[&str] = &["OPEN_FLEET_PROVENANCE", "ORCA_PROVENANCE"];
pub const TRUSTED_BASES: &[&str] = &[
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/main",
    "refs/remotes/origin/master",
];
const FORBIDDEN_ENV_EXACT: &[&str] = &[
    "PATH",
    "PYTHONPATH",
    "HOME",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "IFS",
    "CDPATH",
];
const FORBIDDEN_ENV_PREFIX: &[&str] = &["PYTHON", "LD_", "DYLD_"];
const LEGACY_RUN_DIRS: &[(&str, &str)] = &[(
    "2026-09-14-clean-sweep-self-run",
    "2026-09-14-clean-sweep-tracker",
)];
const TIER_SUFFIXES: &[&str] = &["self-run", "selfrun", "external-run"];
const WIP_ROW_SCHEMA: &str = "wave=<k> builders=<n> reviewers=<n> throughput=<v> latency_median=<v> latency_max=<v> rework=<v> freshness=<v>";

pub type EnforcementKey = (Option<[u8; 32]>, Option<String>, String);

fn run_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^RUN:[ \t\x0b\x0c]*(.+?)[ \t\x0b\x0c\r]*$").expect("regex"))
}

fn field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([a-z_]+)=(\S+)").expect("regex"))
}

fn env_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").expect("regex"))
}

fn python_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^python(?:[0-9]+(?:\.[0-9]+)?)?t?$").expect("regex"))
}

fn xoption_int_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[ \t\r\n\x0c\x0b]*[+-]?[0-9]+$").expect("regex"))
}

fn hex_rev_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{7,40}$").expect("regex"))
}

fn mutation_units_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\*\*Mutation units\*\* \(([^)]*)\)").expect("regex"))
}

fn count_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]+$").expect("regex"))
}

fn measured_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]\S*$").expect("regex"))
}

fn date_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})-").expect("regex"))
}

fn negative_number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^-(?:[0-9]+|[0-9]*\.[0-9]+)(?:[eE][+-]?[0-9]+)?$").expect("regex")
    })
}

fn invocation_re(manifest: &str) -> Regex {
    let pat = format!(
        r"verify\.py[^\n]*--manifest\s+{}(?:\s|$)",
        regex::escape(manifest)
    );
    Regex::new(&pat).expect("valid invocation regex")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn prefix_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn py_repr_str(s: &str) -> String {
    let use_double = s.contains('\'') && !s.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn py_repr_value(val: Option<&Value>) -> String {
    match val {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => py_repr_str(s),
        Some(other) => other.to_string(),
    }
}

fn py_str_value(val: Option<&Value>) -> String {
    match val {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn fmt_py_str_list(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn fmt_py_str_list_owned(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn fmt_py_int_list(items: &[usize]) -> String {
    let inner: Vec<String> = items.iter().map(|n| n.to_string()).collect();
    format!("[{}]", inner.join(", "))
}

pub fn parse_run_header(text: &str) -> Result<BTreeMap<String, String>, String> {
    let headers: Vec<String> = run_header_re()
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect();
    if headers.is_empty() {
        return Err(
            "no 'RUN:' header — a tier advance needs one line naming the mission, the tier, the commit its inventory was computed at, its manifest, and the verifier outcome".to_string(),
        );
    }
    if headers.len() > 1 {
        return Err(format!(
            "{} 'RUN:' headers — exactly one is the report's identity",
            headers.len()
        ));
    }
    let mut fields = BTreeMap::new();
    for caps in field_re().captures_iter(&headers[0]) {
        fields.insert(caps[1].to_string(), caps[2].to_string());
    }
    let missing: Vec<&str> = REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|&f| fields.get(f).is_none_or(|v| v.is_empty()))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "RUN: header is missing {} (want {})",
            fmt_py_str_list(&missing),
            fmt_py_str_list(REQUIRED_FIELDS)
        ));
    }
    Ok(fields)
}

pub fn is_shallow(root: &Path) -> bool {
    match run_git_repo(root, &["rev-parse", "--is-shallow-repository"], &[]) {
        Ok(out) => out.code == 0 && String::from_utf8_lossy(&out.stdout).trim() == "true",
        Err(_) => false,
    }
}

pub fn path_exists_at(rev: &str, path_text: &str, root: &Path) -> bool {
    let spec = format!("{rev}:{path_text}");
    run_git_repo(root, &["cat-file", "-e", &spec], &[])
        .map(|o| o.code == 0)
        .unwrap_or(false)
}

pub fn blob_at(rev: &str, path_text: &str, root: &Path) -> Option<Vec<u8>> {
    let spec = format!("{rev}:{path_text}");
    let out = run_git_repo(root, &["cat-file", "blob", &spec], &[]).ok()?;
    if out.code == 0 {
        Some(out.stdout)
    } else {
        None
    }
}

pub fn tree_of(rev: &str, root: &Path) -> Option<String> {
    let spec = format!("{rev}^{{tree}}");
    let out = run_git_repo(root, &["rev-parse", &spec], &[]).ok()?;
    let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.code == 0 && !trimmed.is_empty() {
        Some(trimmed)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
enum PathPiece {
    Prefix(OsString),
    Root,
    Cur,
    Parent,
    Normal(OsString),
}

fn path_to_pieces(p: &Path) -> Vec<PathPiece> {
    p.components()
        .map(|c| match c {
            Component::Prefix(pr) => PathPiece::Prefix(pr.as_os_str().to_os_string()),
            Component::RootDir => PathPiece::Root,
            Component::CurDir => PathPiece::Cur,
            Component::ParentDir => PathPiece::Parent,
            Component::Normal(n) => PathPiece::Normal(n.to_os_string()),
        })
        .collect()
}

/// Non-strict path resolution matching Python's `Path.resolve()` (resolves symlinks along
/// existing prefixes and normalizes trailing components that do not exist on disk).
fn resolve_path_nonstrict(path: &Path) -> Result<PathBuf, std::io::Error> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut queue: VecDeque<PathPiece> = path_to_pieces(&abs).into_iter().collect();
    let mut resolved = PathBuf::new();
    let mut symlinks = 0usize;

    while let Some(piece) = queue.pop_front() {
        match piece {
            PathPiece::Prefix(p) => resolved.push(p),
            PathPiece::Root => resolved.push(std::path::MAIN_SEPARATOR_STR),
            PathPiece::Cur => {}
            PathPiece::Parent => {
                if resolved.file_name().is_some() {
                    resolved.pop();
                }
            }
            PathPiece::Normal(part) => {
                resolved.push(&part);
                if let Ok(meta) = fs::symlink_metadata(&resolved) {
                    if meta.file_type().is_symlink() {
                        symlinks += 1;
                        if symlinks > 40 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "symlink loop",
                            ));
                        }
                        let target = fs::read_link(&resolved)?;
                        let target_pieces = path_to_pieces(&target);
                        if target.is_absolute() {
                            resolved.clear();
                        } else {
                            resolved.pop();
                        }
                        for tp in target_pieces.into_iter().rev() {
                            queue.push_front(tp);
                        }
                    }
                }
            }
        }
    }
    Ok(resolved)
}

fn is_repo_verifier(token: &str, root: &Path) -> bool {
    let path = Path::new(token);
    let mut parts: Vec<&OsStr> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => return false,
            Component::RootDir => parts.push(OsStr::new("/")),
            Component::Prefix(p) => parts.push(p.as_os_str()),
            Component::Normal(s) => parts.push(s),
        }
    }
    if parts.len() < 3 {
        return false;
    }
    let tail = &parts[parts.len() - 3..];
    let matches_tail = tail
        .iter()
        .zip(VERIFIER_PATH_PARTS.iter())
        .all(|(a, b)| a.to_str() == Some(*b));
    if !matches_tail {
        return false;
    }
    let Ok(resolved_root) = resolve_path_nonstrict(root) else {
        return false;
    };
    let Ok(resolved_target) = resolve_path_nonstrict(&resolved_root.join(path)) else {
        return false;
    };
    let expected = resolved_root
        .join(VERIFIER_PATH_PARTS[0])
        .join(VERIFIER_PATH_PARTS[1])
        .join(VERIFIER_PATH_PARTS[2]);
    resolved_target == expected
}

fn scratch_roots() -> Vec<PathBuf> {
    let mut raw = vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm"),
    ];
    if let Some(tmpdir) = env::var_os("TMPDIR") {
        if !tmpdir.is_empty() {
            raw.push(PathBuf::from(tmpdir));
        }
    }
    raw.into_iter()
        .filter_map(|p| resolve_path_nonstrict(&p).ok())
        .collect()
}

pub fn is_python_interpreter(token: &str, root: &Path) -> bool {
    let path = Path::new(token);
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !python_name_re().is_match(name) {
        return false;
    }
    if !token.contains('/') {
        return true;
    }
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let Ok(repo) = resolve_path_nonstrict(root) else {
        return false;
    };
    let Ok(resolved) = resolve_path_nonstrict(path) else {
        return false;
    };
    if resolved.starts_with(&repo) {
        return false;
    }
    !scratch_roots().iter().any(|s| resolved.starts_with(s))
}

fn valid_python_xoption(option: &str) -> bool {
    let (name, has_sep, value) = match option.split_once('=') {
        Some((n, v)) => (n, true, v),
        None => (option, false, ""),
    };
    if name == "utf8" {
        return !has_sep || matches!(value, "0" | "1");
    }
    if name == "gil" {
        return matches!(value, "0" | "1");
    }
    if name == "frozen_modules" {
        return matches!(value, "" | "on" | "off");
    }
    if !matches!(name, "int_max_str_digits" | "cpu_count" | "tracemalloc") {
        return true;
    }
    if !has_sep {
        return name == "tracemalloc";
    }
    if name == "cpu_count" && value == "default" {
        return true;
    }
    if !value.is_empty() && !xoption_int_re().is_match(value) {
        return false;
    }
    let parse_src = if value.is_empty() { "0" } else { value.trim() };
    let Ok(number) = parse_src.parse::<i64>() else {
        return false;
    };
    if !(0..=2_147_483_647).contains(&number) {
        return false;
    }
    if name == "int_max_str_digits" {
        return number == 0 || number >= 640;
    }
    if name == "cpu_count" {
        return number >= 1;
    }
    number <= 65_535
}

fn python_script_index(argv: &[String], mut i: usize) -> usize {
    let mut xoptions: HashMap<String, String> = HashMap::new();
    while i < argv.len() && argv[i].starts_with('-') {
        let token = &argv[i];
        if token == "--" {
            i += 1;
            break;
        }
        if token == "--check-hash-based-pycs" {
            if i + 1 >= argv.len()
                || !matches!(argv[i + 1].as_str(), "always" | "default" | "never")
            {
                return argv.len();
            }
            i += 2;
            continue;
        }
        if token == "-" || token.starts_with("--") {
            return argv.len();
        }
        let body = &token[1..];
        for (rel_idx, flag) in body.char_indices() {
            if flag == 'W' || flag == 'X' {
                let rest = &body[rel_idx + flag.len_utf8()..];
                let value = if rest.is_empty() {
                    i += 1;
                    if i >= argv.len() {
                        return argv.len();
                    }
                    argv[i].as_str()
                } else {
                    rest
                };
                if flag == 'X' {
                    let key = value.split('=').next().unwrap_or(value).to_string();
                    xoptions.entry(key).or_insert_with(|| value.to_string());
                }
                break;
            }
            if !"bBdEiIOPqRsSuvx".contains(flag) {
                return argv.len();
            }
        }
        i += 1;
    }
    if xoptions.values().all(|v| valid_python_xoption(v)) {
        i
    } else {
        argv.len()
    }
}

fn is_forbidden_env_var(name: &str) -> bool {
    FORBIDDEN_ENV_EXACT.contains(&name) || FORBIDDEN_ENV_PREFIX.iter().any(|p| name.starts_with(p))
}

/// POSIX shlex splitter matching Python's `shlex.split(s, comments=True)`.
fn shlex_split_comments(input: &str) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Space,
        Word,
        SingleQuote,
        DoubleQuote,
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match state {
            State::Space => {
                if matches!(ch, ' ' | '\t' | '\r' | '\n') {
                    continue;
                }
                if ch == '#' {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                    continue;
                }
                if ch == '\\' {
                    let Some(escaped) = chars.next() else {
                        return Err("No escaped character".to_string());
                    };
                    cur.push(escaped);
                    state = State::Word;
                } else if ch == '\'' {
                    quoted = true;
                    state = State::SingleQuote;
                } else if ch == '"' {
                    quoted = true;
                    state = State::DoubleQuote;
                } else {
                    cur.push(ch);
                    state = State::Word;
                }
            }
            State::Word => {
                if matches!(ch, ' ' | '\t' | '\r' | '\n') {
                    tokens.push(std::mem::take(&mut cur));
                    quoted = false;
                    state = State::Space;
                } else if ch == '#' {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                    if !cur.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut cur));
                        quoted = false;
                    }
                    state = State::Space;
                } else if ch == '\\' {
                    let Some(escaped) = chars.next() else {
                        return Err("No escaped character".to_string());
                    };
                    cur.push(escaped);
                } else if ch == '\'' {
                    quoted = true;
                    state = State::SingleQuote;
                } else if ch == '"' {
                    quoted = true;
                    state = State::DoubleQuote;
                } else {
                    cur.push(ch);
                }
            }
            State::SingleQuote => {
                if ch == '\'' {
                    state = State::Word;
                } else {
                    cur.push(ch);
                }
            }
            State::DoubleQuote => {
                if ch == '"' {
                    state = State::Word;
                } else if ch == '\\' {
                    let Some(next) = chars.next() else {
                        return Err("No escaped character".to_string());
                    };
                    if next == '"' || next == '\\' {
                        cur.push(next);
                    } else {
                        cur.push('\\');
                        cur.push(next);
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }

    match state {
        State::SingleQuote | State::DoubleQuote => Err("No closing quotation".to_string()),
        State::Word => {
            if !cur.is_empty() || quoted {
                tokens.push(cur);
            }
            Ok(tokens)
        }
        State::Space => Ok(tokens),
    }
}

fn looks_like_option(tok: &str) -> bool {
    if !tok.starts_with('-') || tok == "-" {
        return false;
    }
    !negative_number_re().is_match(tok)
}

fn parsed_manifest(rest: &[String]) -> Option<String> {
    for tok in rest {
        if tok == "--" {
            break;
        }
        let opt = tok.split('=').next().unwrap_or(tok);
        if opt == "-h"
            || opt.starts_with("--h")
            || (opt.starts_with('-') && !opt.starts_with("--") && opt[1..].contains('h'))
        {
            return None;
        }
    }
    let mut manifest: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        let tok = &rest[i];
        if tok == "--" {
            break;
        }
        if tok == "--manifest" {
            if i + 1 >= rest.len() || looks_like_option(&rest[i + 1]) {
                return None;
            }
            manifest = Some(rest[i + 1].clone());
            i += 2;
        } else if let Some(val) = tok.strip_prefix("--manifest=") {
            manifest = Some(val.to_string());
            i += 1;
        } else {
            i += 1;
        }
    }
    manifest
}

pub fn executes_verifier(cmd: &str, manifest_path: &str, root: &Path) -> bool {
    let Ok(argv) = shlex_split_comments(cmd) else {
        return false;
    };
    let mut i = 0usize;
    while i < argv.len() && (argv[i] == "env" || env_assign_re().is_match(&argv[i])) {
        if env_assign_re().is_match(&argv[i]) {
            let var_name = argv[i].split('=').next().unwrap_or("");
            if is_forbidden_env_var(var_name) {
                return false;
            }
        }
        i += 1;
    }
    if i >= argv.len() {
        return false;
    }
    if is_python_interpreter(&argv[i], root) {
        i = python_script_index(&argv, i + 1);
        if i >= argv.len() {
            return false;
        }
    }
    if !is_repo_verifier(&argv[i], root) {
        return false;
    }
    parsed_manifest(&argv[i + 1..]).as_deref() == Some(manifest_path)
}

pub fn verifier_ran(
    manifest_path: &str,
    rev: &str,
    root: &Path,
    verifier_verdict: Option<&str>,
) -> Vec<String> {
    let Some(raw) = blob_at(rev, manifest_path, root) else {
        return vec![format!(
            "the graded manifest {manifest_path} cannot be read at {rev}"
        )];
    };
    let text = match std::str::from_utf8(&raw) {
        Ok(t) => t,
        Err(err) => {
            return vec![format!(
                "the graded manifest {manifest_path} at {rev} is not readable JSON ({err})"
            )];
        }
    };
    let val: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(err) => {
            return vec![format!(
                "the graded manifest {manifest_path} at {rev} is not readable JSON ({err})"
            )];
        }
    };
    let Some(manifest) = val.as_object() else {
        return vec![format!(
            "the graded manifest {manifest_path} at {rev} is not a JSON object"
        )];
    };

    let records: Vec<&Map<String, Value>> = manifest
        .get("commands")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_object()).collect())
        .unwrap_or_default();
    let verifier: Vec<&Map<String, Value>> = records
        .iter()
        .copied()
        .filter(|c| {
            c.get("cmd")
                .and_then(|v| v.as_str())
                .is_some_and(|cmd| executes_verifier(cmd, manifest_path, root))
        })
        .collect();
    if verifier.is_empty() {
        let seen = if records.is_empty() {
            "nothing".to_string()
        } else {
            records
                .iter()
                .map(|c| py_repr_value(c.get("cmd")))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return vec![format!(
            "the graded manifest {manifest_path} records no commands[] entry running verify.py against itself — a tier costs a RUN, not a sentence about one. Wrap the verifier in evidence-run.py so the ledger carries it (#286). Recorded there: {seen}"
        )];
    }

    let want_exit: Option<i64> = match verifier_verdict {
        Some("GREEN") => Some(0),
        Some("RED") => Some(2),
        _ => None,
    };

    let mut problems: Vec<String> = Vec::new();
    for rec in verifier {
        let line = rec.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        let digest_val = rec.get("cmd_sha256");
        let actual = sha256_hex(line.as_bytes());
        if digest_val.and_then(|v| v.as_str()) != Some(actual.as_str()) {
            let shown_digest = py_str_value(digest_val);
            problems.push(format!(
                "its cmd_sha256 {shown_digest} does not hash its own command line ({actual})"
            ));
            continue;
        }
        let wtree = match rec.get("wtree").and_then(|v| v.as_str()) {
            Some(w) if !w.is_empty() => w,
            _ => {
                problems
                    .push("it carries no wtree, so it is bound to no content at all".to_string());
                continue;
            }
        };
        let Some(tree) = tree_of(wtree, root) else {
            problems.push(format!(
                "its wtree {}… does not resolve to a tree object in this repository",
                prefix_chars(wtree, 12)
            ));
            continue;
        };
        if EMPTY_TREES.contains(&tree.as_str()) {
            problems.push(format!(
                "its wtree {}… is git's built-in EMPTY tree, which resolves in any repository and binds the record to no content",
                prefix_chars(wtree, 12)
            ));
            continue;
        }
        if let Some(want) = want_exit {
            let exit_val = rec.get("exit");
            if exit_val.and_then(|v| v.as_i64()) != Some(want) {
                let verdict_str = verifier_verdict.unwrap_or("");
                problems.push(format!(
                    "its exit code {} does not match RUN: verifier={verdict_str} (expected {want})",
                    py_repr_value(exit_val)
                ));
                continue;
            }
        }
        return Vec::new();
    }
    vec![format!(
        "the graded manifest {manifest_path} records a verify.py run that binds to nothing: {}",
        problems.join("; ")
    )]
}

fn match_signed_arg_flag(opt: &str) -> Option<&'static str> {
    if !opt.starts_with("--") || opt.len() < 3 {
        return None;
    }
    let mut exact = None;
    let mut prefix_hits: Vec<&'static str> = Vec::new();
    for &key in SIGNED_ARGS {
        let flag = format!("--{}", key.replace('_', "-"));
        if flag == opt {
            exact = Some(key);
            break;
        }
        if flag.starts_with(opt) {
            prefix_hits.push(key);
        }
    }
    if exact.is_some() {
        return exact;
    }
    if prefix_hits.len() == 1 {
        return Some(prefix_hits[0]);
    }
    None
}

fn parse_signed_args_slice(slice: &[String]) -> Option<BTreeMap<String, Value>> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for &key in SIGNED_ARGS {
        let default_val = if SWITCH_ARGS.contains(&key) {
            Value::Bool(false)
        } else {
            Value::Null
        };
        out.insert(key.to_string(), default_val);
    }
    let mut i = 0usize;
    while i < slice.len() {
        let tok = &slice[i];
        if tok == "--" {
            break;
        }
        if tok.starts_with("--") {
            let (opt, inline_val) = match tok.split_once('=') {
                Some((o, v)) => (o, Some(v)),
                None => (tok.as_str(), None),
            };
            if let Some(key) = match_signed_arg_flag(opt) {
                if SWITCH_ARGS.contains(&key) {
                    if inline_val.is_some() {
                        return None;
                    }
                    out.insert(key.to_string(), Value::Bool(true));
                    i += 1;
                } else if let Some(val) = inline_val {
                    out.insert(key.to_string(), Value::String(val.to_string()));
                    i += 1;
                } else {
                    if i + 1 >= slice.len() || looks_like_option(&slice[i + 1]) {
                        return None;
                    }
                    out.insert(key.to_string(), Value::String(slice[i + 1].clone()));
                    i += 2;
                }
                continue;
            }
        }
        i += 1;
    }
    Some(out)
}

pub fn invocation_args(text: &str, manifest: &str) -> Vec<BTreeMap<String, Value>> {
    let re = invocation_re(manifest);
    let mut out = Vec::new();
    for line in split_python_lines(text) {
        if !re.is_match(line) {
            continue;
        }
        let Ok(argv) = shlex_split_comments(line) else {
            continue;
        };
        let Some(pos) = argv.iter().position(|tok| tok.ends_with("verify.py")) else {
            continue;
        };
        if let Some(known) = parse_signed_args_slice(&argv[pos + 1..]) {
            out.push(known);
        }
    }
    out
}

pub fn grading_base(root: &Path, base: Option<&str>) -> Option<String> {
    let non_empty_base = base.filter(|b| !b.is_empty());
    let single;
    let candidates: &[&str] = match non_empty_base {
        Some(b) => {
            single = [b];
            &single
        }
        None => GRADING_BASES,
    };
    for &cand in candidates {
        let spec = format!("{cand}^{{commit}}");
        if let Ok(out) = run_git_repo(root, &["rev-parse", "--verify", "-q", &spec], &[]) {
            let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.code == 0 && !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

pub fn sound_lane() -> Option<String> {
    gitexec_sound_lane()
}

pub fn trusted_base(root: &Path, base: Option<&str>) -> Result<(String, String), String> {
    let non_empty_base = base.filter(|b| !b.is_empty());
    let single;
    let candidates: &[&str] = match non_empty_base {
        Some(b) => {
            single = [b];
            &single
        }
        None => TRUSTED_BASES,
    };
    let mut skipped: Vec<String> = Vec::new();
    for &name in candidates {
        if name.starts_with('-') {
            return Err(format!(
                "--base {} is an option, not a ref",
                py_repr_str(name)
            ));
        }
        match remote_tracking_commit(root, name) {
            Ok((commit, target)) => {
                let via = if target != name && target != commit {
                    format!(" -> {target}")
                } else {
                    String::new()
                };
                return Ok((
                    commit.clone(),
                    format!("{name}{via} = {}", prefix_chars(&commit, 12)),
                ));
            }
            Err((_, why)) => {
                if non_empty_base.is_some() {
                    return Err(format!("--base {} {why}", py_repr_str(name)));
                }
                skipped.push(format!("{name} {why}"));
            }
        }
    }
    let base_why = format!(
        "no remote-tracking base resolves (tried {})",
        TRUSTED_BASES.join(", ")
    );
    if skipped.is_empty() {
        Err(base_why)
    } else {
        Err(format!("{base_why}; {}", skipped.join("; ")))
    }
}

pub fn sound_lane_refusal(root: &Path, base: Option<&str>) -> Option<String> {
    let lane = sound_lane()?;
    match trusted_base(root, base) {
        Ok(_) => None,
        Err(why) => Some(format!(
            "{lane} claims a sound lane, but {why}: the key and the mutation-unit policy are read there only at a commit id or a ref whose final target is remote-tracking, never a local branch or HEAD — could-not-run, never a pass"
        )),
    }
}

pub fn commit_object(rev: &str, root: &Path) -> Option<String> {
    let arg = format!("--disambiguate={}", rev.to_ascii_lowercase());
    let out = run_git_repo(root, &["rev-parse", &arg], &[]).ok()?;
    if out.code != 0 {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut commits: Vec<String> = Vec::new();
    for oid in stdout.split_whitespace() {
        if let Ok(kind_out) = run_git_repo(root, &["cat-file", "-t", oid], &[]) {
            if String::from_utf8_lossy(&kind_out.stdout).trim() == "commit" {
                commits.push(oid.to_string());
            }
        }
    }
    if commits.len() == 1 {
        Some(commits.remove(0))
    } else {
        None
    }
}

pub fn is_ancestor(rev: &str, base: &str, root: &Path) -> bool {
    run_git_repo(root, &["merge-base", "--is-ancestor", rev, base], &[])
        .map(|o| o.code == 0)
        .unwrap_or(false)
}

pub fn key_rev(rev: &str, root: &Path, base: Option<&str>) -> (Option<String>, String) {
    if sound_lane().is_some() {
        return match trusted_base(root, base) {
            Err(_) => (
                None,
                sound_lane_refusal(root, base).unwrap_or_else(|| "no trusted base".to_string()),
            ),
            Ok((tip, where_s)) => {
                if is_ancestor(rev, &tip, root) {
                    (
                        Some(rev.to_string()),
                        format!("the pin, an ancestor of the trusted base {where_s}"),
                    )
                } else {
                    (
                        Some(tip),
                        format!(
                            "the trusted base {where_s} — the pin {} is not an ancestor of it, so the key is read where the pin cannot choose",
                            prefix_chars(rev, 12)
                        ),
                    )
                }
            }
        };
    }
    let Some(tip) = grading_base(root, base) else {
        return (
            None,
            format!(
                "no grading base resolves (tried {})",
                GRADING_BASES.join(", ")
            ),
        );
    };
    if base.is_none() && blob_at(rev, PUBKEY_PIN, root).is_some() {
        let non_head_resolves = GRADING_BASES[..GRADING_BASES.len() - 1].iter().any(|&c| {
            let spec = format!("{c}^{{commit}}");
            run_git_repo(root, &["rev-parse", "--verify", "-q", &spec], &[])
                .map(|o| o.code == 0)
                .unwrap_or(false)
        });
        if !non_head_resolves {
            return (
                None,
                "only HEAD resolves as a grading base and the pin carries a key — the pin would choose its own judge; refusing the self-pinned fallback (h409 O-3.3)".to_string(),
            );
        }
    }
    if is_ancestor(rev, &tip, root) {
        (
            Some(rev.to_string()),
            format!(
                "the pin, an ancestor of the grading base {}",
                prefix_chars(&tip, 12)
            ),
        )
    } else {
        (
            Some(tip.clone()),
            format!(
                "the grading base {} — the pin {} is not an ancestor of it, so the key is read where the pin cannot choose",
                prefix_chars(&tip, 12),
                prefix_chars(rev, 12)
            ),
        )
    }
}

pub fn enforcement_key(rev: &str, root: &Path, base: Option<&str>) -> EnforcementKey {
    let (at_opt, why) = key_rev(rev, root, base);
    let Some(at) = at_opt else {
        return (
            None,
            None,
            format!("{why} — the unsigned lane needs an ancestry proof, so the claim fails closed"),
        );
    };
    let Some(pin) = blob_at(&at, PUBKEY_PIN, root) else {
        return (None, Some(at), why);
    };
    let text = match std::str::from_utf8(&pin) {
        Ok(s) => s,
        Err(err) => {
            return (
                None,
                None,
                format!("{PUBKEY_PIN} at {at} is malformed ({err}) — fail-closed"),
            );
        }
    };
    let raw = match hex::decode(text.trim()) {
        Ok(b) => b,
        Err(err) => {
            return (
                None,
                None,
                format!("{PUBKEY_PIN} at {at} is malformed ({err}) — fail-closed"),
            );
        }
    };
    let Ok(pub_bytes): Result<[u8; 32], _> = raw.try_into() else {
        return (
            None,
            None,
            format!("{PUBKEY_PIN} at {at} is malformed (not a 32-byte hex key) — fail-closed"),
        );
    };
    (Some(pub_bytes), Some(at), why)
}

pub fn signed_inventory(
    lines: &[String],
    entries: &[InventoryEntry],
    rev: &str,
    root: &Path,
    base: Option<&str>,
) -> Vec<String> {
    let (pub_opt, at_opt, why) = enforcement_key(rev, root, base);
    let Some(at) = at_opt else {
        return vec![why];
    };
    let envelope = match find_signature(lines) {
        Ok(found) => found.map(|(_, env)| env),
        Err(err) => return vec![format!("integrity inventory {SIGNATURE_TAG}: {err}")],
    };
    if pub_opt.is_none() && envelope.is_none() {
        return Vec::new();
    }
    let Some(pub_bytes) = pub_opt else {
        return vec![format!(
            "integrity inventory carries an {SIGNATURE_TAG} but no {PUBKEY_PIN} is committed at {at} — nothing can verify it, so the claim fails closed (#386)"
        )];
    };
    let Some(env_map) = envelope else {
        return vec![format!(
            "{PUBKEY_PIN} is committed at {at} ({why}), so an UNSIGNED integrity inventory no longer binds — sign its entry set with `inventory.py sign --key <coordinator seed>` (#386)"
        )];
    };
    let signed = match verify_signature(&env_map, entries, &pub_bytes) {
        Ok(d) => d,
        Err(problem) => {
            return vec![format!(
                "integrity inventory signature does not bind: {problem} (key: {PUBKEY_PIN} at {at})"
            )];
        }
    };
    if signed != inventory_digest(entries) {
        return vec![format!(
            "integrity inventory signature does not bind: the verifier returned {}, not this inventory's digest (key: {PUBKEY_PIN} at {at})",
            py_repr_str(&signed)
        )];
    }
    Vec::new()
}

pub fn signed_transcript(
    fields: &BTreeMap<String, String>,
    rev: &str,
    run_dir: Option<&str>,
    root: &Path,
    base: Option<&str>,
    text: &str,
) -> Vec<String> {
    let (pub_opt, at_opt, why) = enforcement_key(rev, root, base);
    let Some(at) = at_opt else {
        return vec![why];
    };
    let transcript = fields.get("transcript");
    if pub_opt.is_none() && transcript.is_none() {
        return Vec::new();
    }
    let Some(pub_bytes) = pub_opt else {
        let t = transcript.map(|s| s.as_str()).unwrap_or("");
        return vec![format!(
            "RUN: transcript={t} is named but no {PUBKEY_PIN} is committed at {at} — nothing can verify it, so the claim fails closed (#281)"
        )];
    };
    let Some(transcript) = transcript else {
        return vec![format!(
            "{PUBKEY_PIN} is committed at {at} ({why}), so a ledger entry alone no longer proves the verifier ran — the RUN: header must name transcript=<path>, the coordinator-signed verdict envelope (verify.py --transcript-out/--transcript-key, or dispatch-sign.py sign-transcript) (#281)"
        )];
    };
    if let Some(rd) = run_dir {
        if !transcript.starts_with(&format!("{rd}/")) {
            return vec![format!(
                "RUN: transcript={transcript} is outside this run's own directory {rd}/ — a run is graded on its own verdict, not another run's"
            )];
        }
    }
    let Some(raw) = blob_at(rev, transcript, root) else {
        return vec![format!(
            "RUN: transcript={transcript} cannot be read at {rev}"
        )];
    };
    let raw_str = match std::str::from_utf8(&raw) {
        Ok(s) => s,
        Err(err) => {
            return vec![format!(
                "RUN: transcript={transcript} at {rev} is not readable JSON ({err})"
            )];
        }
    };
    let val: Value = match serde_json::from_str(raw_str) {
        Ok(v) => v,
        Err(err) => {
            return vec![format!(
                "RUN: transcript={transcript} at {rev} is not readable JSON ({err})"
            )];
        }
    };
    let (record, sig_b64) = match val.as_object() {
        Some(env_obj) => match (
            env_obj.get("record").and_then(|v| v.as_object()),
            env_obj.get("sig_b64").and_then(|v| v.as_str()),
        ) {
            (Some(r), Some(s)) => (r, s),
            _ => {
                return vec![format!(
                    "RUN: transcript={transcript} is an UNSIGNED verdict (no record/sig_b64 envelope) and {PUBKEY_PIN} is committed at {at} — rejected; sign it with the coordinator's seed (#281)"
                )];
            }
        },
        None => {
            return vec![format!(
                "RUN: transcript={transcript} is an UNSIGNED verdict (no record/sig_b64 envelope) and {PUBKEY_PIN} is committed at {at} — rejected; sign it with the coordinator's seed (#281)"
            )];
        }
    };
    let sig = match decode_strict(sig_b64) {
        Ok(s) => s,
        Err(err) => {
            return vec![format!(
                "RUN: transcript={transcript} sig_b64 is malformed ({err}) — fail-closed"
            )];
        }
    };
    let canonical = canonical_record(record, TRANSCRIPT_FIELDS);
    if !verify_bytes(&sig, &canonical, &pub_bytes) {
        return vec![format!(
            "RUN: transcript={transcript} signature INVALID for the {PUBKEY_PIN} committed at {at} — not the coordinator's verdict (forged, tampered, or another key) (#281)"
        )];
    }

    let mut problems: Vec<String> = Vec::new();
    let manifest = fields.get("manifest").map(|s| s.as_str()).unwrap_or("");
    if record.get("manifest").and_then(|v| v.as_str()) != Some(manifest) {
        problems.push(format!(
            "it judges manifest {}, not {manifest}",
            py_repr_value(record.get("manifest"))
        ));
    }
    match blob_at(rev, manifest, root) {
        None => problems.push(format!(
            "the graded manifest {manifest} cannot be read at {rev}, so there are no bytes to bind"
        )),
        Some(graded) => {
            let rec_sha_val = record.get("manifest_sha256");
            if rec_sha_val.is_none() || rec_sha_val == Some(&Value::Null) {
                problems
                    .push("it signs no manifest_sha256 — a verdict over unknown bytes".to_string());
            } else {
                let actual_sha = sha256_hex(&graded);
                if rec_sha_val.and_then(|v| v.as_str()) != Some(actual_sha.as_str()) {
                    let rec_str = py_str_value(rec_sha_val);
                    problems.push(format!(
                        "its manifest_sha256 {}… is not the graded manifest's bytes at {rev} ({}…)",
                        prefix_chars(&rec_str, 12),
                        &actual_sha[..12]
                    ));
                }
            }
        }
    }
    let verifier_field = fields.get("verifier").map(|s| s.as_str()).unwrap_or("");
    let want: i64 = if verifier_field == "GREEN" { 0 } else { 2 };
    if record.get("exit").and_then(|v| v.as_i64()) != Some(want) {
        problems.push(format!(
            "its exit {} disagrees with RUN: verifier={verifier_field} (expected exit {want})",
            py_repr_value(record.get("exit"))
        ));
    }

    match record.get("args").and_then(|v| v.as_object()) {
        Some(signed_map) if !signed_map.is_empty() => {
            let expected_keys: BTreeSet<&str> = SIGNED_ARGS.iter().copied().collect();
            let present_keys: BTreeSet<&str> = signed_map.keys().map(|k| k.as_str()).collect();
            let missing: Vec<String> = expected_keys
                .difference(&present_keys)
                .map(|s| (*s).to_string())
                .collect();
            let unexpected: Vec<String> = present_keys
                .difference(&expected_keys)
                .map(|s| (*s).to_string())
                .collect();
            if !missing.is_empty() || !unexpected.is_empty() {
                let extra = if unexpected.is_empty() {
                    String::new()
                } else {
                    format!(", unexpected keys {}", fmt_py_str_list_owned(&unexpected))
                };
                problems.push(format!(
                    "its signed argument tuple is partial — missing keys {}{extra} — the full verifier policy tuple must be signed, not a subset (a transcript may omit no control it was reached under)",
                    fmt_py_str_list_owned(&missing)
                ));
            } else {
                let shown = invocation_args(text, manifest);
                let any_match = shown
                    .iter()
                    .any(|inv| SIGNED_ARGS.iter().all(|&k| inv.get(k) == signed_map.get(k)));
                if !any_match {
                    let parts: Vec<String> = SIGNED_ARGS
                        .iter()
                        .filter_map(|&k| {
                            let v = signed_map.get(k);
                            if matches!(v, None | Some(Value::Null) | Some(Value::Bool(false))) {
                                None
                            } else {
                                Some(format!("{k}={}", py_repr_value(v)))
                            }
                        })
                        .collect();
                    let summary = if parts.is_empty() {
                        "every flag unset".to_string()
                    } else {
                        parts.join(" ")
                    };
                    problems.push(format!(
                        "its signed argument tuple ({summary}) matches no verify.py invocation the body shows — the verdict was reached under a policy the report does not claim"
                    ));
                }
            }
            let mission = fields.get("mission").map(|s| s.as_str()).unwrap_or("");
            if let Some(mutation) = mutation_missions(root, Some(rev), base) {
                if mutation.contains(mission)
                    && signed_map.get("unit_class").and_then(|v| v.as_str()) != Some("mutation")
                {
                    problems.push(format!(
                        "it was judged as unit_class={}, but {mission} is a mutation-class mission (evidence-manifest.md §3) — a verdict on a lesser class proves nothing about this one",
                        py_repr_value(signed_map.get("unit_class"))
                    ));
                }
            }
        }
        _ => {
            problems.push(
                "it signs no argument tuple, so under which policy the verdict was reached is unknown".to_string(),
            );
        }
    }

    let files = record
        .get("toolchain")
        .and_then(|v| v.as_object())
        .and_then(|tc| tc.get("files"))
        .and_then(|f| f.as_object());
    match files {
        None => {
            problems.push(format!(
                "its toolchain names no file set (toolchain.files) — which verifier reached the verdict is unknown; a verify_sha256 alone covers one of the {} files the verifier loads (h409 F-5)",
                TOOLCHAIN_FILES.len()
            ));
        }
        Some(files_map) => {
            for &name in TOOLCHAIN_FILES {
                let signed_sha = files_map.get(name).and_then(|v| v.as_str());
                let at_pin = blob_at(rev, &format!("runtime/scripts/{name}"), root);
                match (signed_sha, at_pin) {
                    (None, _) => {
                        problems.push(format!(
                            "its toolchain.files does not name runtime/scripts/{name}, a module the verifier loads — a partial set binds no verifier identity"
                        ));
                    }
                    (Some(s), None) => {
                        problems.push(format!(
                            "runtime/scripts/{name} cannot be read at {rev}, so the signed toolchain hash {}… binds to no file at the pin",
                            prefix_chars(s, 12)
                        ));
                    }
                    (Some(s), Some(pin_bytes)) => {
                        let actual = sha256_hex(&pin_bytes);
                        if s != actual {
                            problems.push(format!(
                                "its toolchain.files pins runtime/scripts/{name} at {}…, not the file at {rev} ({}…) — a different verifier (or a substituted sibling) reached this verdict",
                                prefix_chars(s, 12),
                                &actual[..12]
                            ));
                        }
                    }
                }
            }
        }
    }

    if !problems.is_empty() {
        return vec![format!(
            "RUN: transcript={transcript} verifies but does not bind this report: {}",
            problems.join("; ")
        )];
    }
    Vec::new()
}

fn read_at_rev(rev: &str, path_text: &str, root: &Path) -> Option<String> {
    let raw = blob_at(rev, path_text, root)?;
    String::from_utf8(raw).ok()
}

pub fn mutation_missions(
    root: &Path,
    rev: Option<&str>,
    base: Option<&str>,
) -> Option<BTreeSet<String>> {
    let at = match rev.filter(|r| !r.is_empty()) {
        Some(r) => key_rev(r, root, base).0.or_else(|| {
            if sound_lane().is_some() {
                None
            } else {
                Some(r.to_string())
            }
        }),
        None => {
            if sound_lane().is_some() {
                trusted_base(root, base).ok().map(|(c, _)| c)
            } else {
                grading_base(root, base)
            }
        }
    };
    let text = at
        .as_deref()
        .and_then(|a| read_at_rev(a, "runtime/evidence-manifest.md", root))?;
    let caps = mutation_units_re().captures(&text)?;
    let set: BTreeSet<String> = caps[1].split(',').map(|s| s.trim().to_string()).collect();
    Some(set)
}

fn wip_cell_ok(key: &str, value: Option<&str>) -> bool {
    let Some(v) = value else {
        return false;
    };
    if matches!(key, "wave" | "builders" | "reviewers") {
        count_re().is_match(v)
    } else {
        measured_re().is_match(v)
    }
}

pub fn wip_curve_errors(
    text: &str,
    mission: &str,
    root: &Path,
    report_path: &str,
    rev: Option<&str>,
    base: Option<&str>,
) -> Vec<String> {
    let Some(missions) = mutation_missions(root, rev, base) else {
        return Vec::new();
    };
    if !missions.contains(mission) {
        return Vec::new();
    }
    let rows = wip_rows(text);
    if rows.is_empty() {
        return vec![format!(
            "{report_path}: a mutating run records one WIP-curve row per dispatch wave, as a table row carrying {WIP_ROW_SCHEMA} under the report's `{WIP_SECTION}` heading, outside fenced code (docs/runs/TEMPLATE.md, attention-budget.md) — none found; a cap recorded nowhere was never a cap (#365, #387)"
        )];
    }
    let mut errors: Vec<String> = Vec::new();
    for row in &rows {
        if !row.doubled.is_empty() {
            errors.push(format!(
                "{report_path}: WIP-curve row {} carries {} more than once — one value per cell, or the row contradicts itself (#389)",
                py_repr_str(&row.raw),
                fmt_py_str_list_owned(&row.doubled)
            ));
            continue;
        }
        let missing: Vec<&str> = WIP_ROW_KEYS
            .iter()
            .copied()
            .filter(|&k| !wip_cell_ok(k, row.cells.get(k).map(|s| s.as_str())))
            .collect();
        if !missing.is_empty() {
            errors.push(format!(
                "{report_path}: WIP-curve row {} carries no measured {} — the protocol's row is {WIP_ROW_SCHEMA} (attention-budget.md, #389)",
                py_repr_str(&row.raw),
                fmt_py_str_list(&missing)
            ));
        }
    }

    let counts: Vec<String> = match run_header_re().captures(text) {
        Some(caps) => field_re()
            .captures_iter(&caps[1])
            .filter(|c| &c[1] == "waves")
            .map(|c| c[2].to_string())
            .collect(),
        None => Vec::new(),
    };
    if counts.len() > 1 {
        errors.push(format!(
            "{report_path}: RUN: header carries waves= more than once ({}) — one count of the dispatch waves, or the header contradicts itself (#389)",
            fmt_py_str_list_owned(&counts)
        ));
        return errors;
    }
    let declared = counts.first().map(|s| s.as_str());
    let declared_n = declared
        .filter(|d| count_re().is_match(d))
        .and_then(|d| d.parse::<usize>().ok())
        .filter(|&n| n >= 1);
    let Some(n) = declared_n else {
        let shown = declared.unwrap_or("<missing>");
        errors.push(format!(
            "{report_path}: RUN: waves={shown} — a mutating run records the number of dispatch waves it ran as waves=<n> (n ≥ 1); its WIP-curve rows are checked against waves 1..n (attention-budget.md, #389)"
        ));
        return errors;
    };
    let declared_str = declared.unwrap_or("");
    let named: Vec<usize> = rows
        .iter()
        .filter_map(|r| r.cells.get("wave"))
        .filter(|w| count_re().is_match(w))
        .filter_map(|w| w.parse::<usize>().ok())
        .collect();
    let absent: Vec<usize> = (1..=n).filter(|k| !named.contains(k)).collect();
    let mut wave_counts: BTreeMap<usize, usize> = BTreeMap::new();
    for &w in &named {
        *wave_counts.entry(w).or_insert(0) += 1;
    }
    let doubled: Vec<usize> = wave_counts
        .iter()
        .filter(|(_, &c)| c > 1)
        .map(|(&k, _)| k)
        .collect();
    let stray: Vec<usize> = wave_counts
        .keys()
        .copied()
        .filter(|&k| k < 1 || k > n)
        .collect();

    if !absent.is_empty() {
        errors.push(format!(
            "{report_path}: RUN: waves={declared_str} but no WIP-curve row for wave(s) {} — one complete row per recorded wave (attention-budget.md, #389)",
            fmt_py_int_list(&absent)
        ));
    }
    if !doubled.is_empty() {
        errors.push(format!(
            "{report_path}: wave(s) {} carry more than one WIP-curve row — one row per wave, or the curve double-counts it (#389)",
            fmt_py_int_list(&doubled)
        ));
    }
    if !stray.is_empty() {
        errors.push(format!(
            "{report_path}: WIP-curve row(s) for wave(s) {} outside the recorded waves 1..{declared_str} (RUN: waves={declared_str}) (#389)",
            fmt_py_int_list(&stray)
        ));
    }
    errors
}

pub fn run_directory(report: &Path, mission: &str, root: &Path) -> Option<String> {
    let stem = report.file_stem()?.to_str()?;
    let caps = date_prefix_re().captures(stem)?;
    if !stem.contains(mission) {
        return None;
    }
    for &(legacy_stem, legacy_dir) in LEGACY_RUN_DIRS {
        if stem == legacy_stem {
            return Some(format!("docs/runs/{legacy_dir}"));
        }
    }
    let runs_dir = root.join("docs").join("runs");
    let mut names: Vec<String> = vec![stem.to_string()];
    for &tier in TIER_SUFFIXES {
        let suffix = format!("-{tier}");
        if let Some(base) = stem.strip_suffix(&suffix) {
            names.push(base.to_string());
            if tier == "self-run" {
                names.push(format!("{base}-selfrun"));
            }
        }
    }
    let date_len = caps[1].len();
    let mtoks: Vec<&str> = mission.split('-').collect();
    for name in &names {
        let rest = name.get(date_len + 1..).unwrap_or("");
        let tokens: Vec<&str> = rest.split('-').collect();
        let has_contiguous = tokens.windows(mtoks.len()).any(|w| w == mtoks.as_slice());
        if runs_dir.join(name).is_dir() && has_contiguous {
            return Some(format!("docs/runs/{name}"));
        }
    }
    Some(format!("docs/runs/{stem}"))
}

pub fn check_report(
    report_path: &str,
    mission: &str,
    tier: &str,
    root: &Path,
    base: Option<&str>,
) -> Vec<String> {
    if let Some(refusal) = sound_lane_refusal(root, base) {
        return vec![format!("{report_path}: {refusal}")];
    }
    let p = Path::new(report_path);
    let report = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    };
    if !report.is_file() {
        return vec![format!("proof_evidence {report_path} does not exist")];
    }
    let text = match fs::read_to_string(&report) {
        Ok(t) => t,
        Err(err) => return vec![format!("proof_evidence {report_path} is unreadable: {err}")],
    };
    let fields = match parse_run_header(&text) {
        Ok(f) => f,
        Err(err) => return vec![format!("{report_path}: {err}")],
    };

    let mut errors: Vec<String> = Vec::new();
    let f_mission = fields.get("mission").map(|s| s.as_str()).unwrap_or("");
    let f_tier = fields.get("tier").map(|s| s.as_str()).unwrap_or("");
    let f_verifier = fields.get("verifier").map(|s| s.as_str()).unwrap_or("");
    let f_manifest = fields.get("manifest").map(|s| s.as_str()).unwrap_or("");
    let f_inv_at = fields.get("inventory_at").map(|s| s.as_str()).unwrap_or("");

    if f_mission != mission {
        errors.push(format!(
            "{report_path}: RUN: mission={f_mission} but {mission} claims it — a run report belongs to the mission that ran"
        ));
    }
    if f_tier != tier {
        errors.push(format!(
            "{report_path}: RUN: tier={f_tier} but the frontmatter claims {tier}"
        ));
    }
    if !VERIFIER_OUTCOMES.contains(&f_verifier) {
        errors.push(format!(
            "{report_path}: RUN: verifier={f_verifier} — want one of {} (a recorded RED is honest; an unrecorded one is not)",
            fmt_py_str_list(VERIFIER_OUTCOMES)
        ));
    } else if !invocation_re(f_manifest).is_match(&text) {
        errors.push(format!(
            "{report_path}: RUN: verifier={f_verifier} but the body shows no verify.py invocation against {f_manifest} that the outcome could have come from — record the command and its exit code, not a description of them"
        ));
    }

    if !hex_rev_re().is_match(f_inv_at) {
        errors.push(format!(
            "{report_path}: RUN: inventory_at={f_inv_at} must be a commit id (7 to 40 hex) — a ref name binds nothing, since it can move"
        ));
        return errors;
    }
    let resolved = commit_object(f_inv_at, root);
    if resolved.is_none() && rev_exists(f_inv_at, root) {
        errors.push(format!(
            "{report_path}: RUN: inventory_at={f_inv_at} names no single commit object in this repository — a ref spelled in hex binds nothing, since it can move, and an ambiguous prefix binds two"
        ));
        return errors;
    }
    let Some(rev) = resolved else {
        if is_shallow(root) {
            errors.push(format!(
                "{report_path}: RUN: inventory_at={f_inv_at} cannot be resolved because this is a SHALLOW clone (git clone --depth …) — run `{SHALLOW_REMEDY}` in {} and re-run; the pin is checked against full history, never skipped",
                root.display()
            ));
        } else {
            errors.push(format!(
                "{report_path}: RUN: inventory_at={f_inv_at} is not a commit in this repository — an unresolvable pin verifies nothing"
            ));
        }
        return errors;
    };

    if !path_exists_at(&rev, f_manifest, root) {
        errors.push(format!(
            "{report_path}: RUN: manifest={f_manifest} does not exist at {rev}"
        ));
    }
    let run_dir = run_directory(&report, mission, root);
    match &run_dir {
        None => {
            errors.push(format!(
                "{report_path}: filename must be docs/runs/<YYYY-MM-DD>-{mission}-<tier>.md — the run directory is derived from it"
            ));
        }
        Some(rd) if !f_manifest.starts_with(&format!("{rd}/")) => {
            errors.push(format!(
                "{report_path}: RUN: manifest={f_manifest} is outside this run's own directory {rd}/ — a run is graded against its own manifest, not another run's"
            ));
        }
        Some(_) => {}
    }

    for problem in verifier_ran(f_manifest, &rev, root, Some(f_verifier)) {
        errors.push(format!("{report_path}: {problem}"));
    }
    for problem in signed_transcript(&fields, &rev, run_dir.as_deref(), root, base, &text) {
        errors.push(format!("{report_path}: {problem}"));
    }
    errors.extend(wip_curve_errors(
        &text,
        mission,
        root,
        report_path,
        Some(&rev),
        base,
    ));

    let (_rep, lines, entries) = match load_report(&report) {
        Ok(loaded) => loaded,
        Err(exc) => {
            errors.push(format!("{report_path}: integrity inventory: {exc}"));
            return errors;
        }
    };
    for problem in signed_inventory(&lines, &entries, &rev, root, base) {
        errors.push(format!("{report_path}: {problem}"));
    }
    let outcome = match check_entries(&entries, &report, Some(root), Some(&rev)) {
        Ok(o) => o,
        Err(exc) => {
            errors.push(format!("{report_path}: integrity inventory: {exc}"));
            return errors;
        }
    };

    for (path_text, recorded, actual) in &outcome.mismatched {
        errors.push(format!(
            "{report_path}: inventory {path_text} at {rev}: recorded {}…, actual {}…",
            prefix_chars(recorded, 12),
            prefix_chars(actual, 12)
        ));
    }
    if outcome.matched.is_empty() {
        errors.push(format!(
            "{report_path}: inventory verified nothing at {rev} ({} listed path(s) absent there) — the tier is not artifact-bound",
            outcome.missing.len()
        ));
    } else if let Some(ref rd) = run_dir {
        let prefix = format!("{rd}/");
        if !outcome.matched.iter().any(|p| p.starts_with(&prefix)) {
            errors.push(format!(
                "{report_path}: no verified inventory path lives in this run's own directory {rd}/ — borrowing another run's artifacts is not evidence of this one"
            ));
        }
    }

    if !outcome.matched.iter().any(|p| p == f_manifest) {
        let where_s = if outcome.mismatched.iter().any(|(p, _, _)| p == f_manifest) {
            "hashes differently"
        } else if !outcome.missing.iter().any(|p| p == f_manifest) {
            "is not in the inventory at all"
        } else {
            "is listed but absent at that commit"
        };
        errors.push(format!(
            "{report_path}: the graded manifest {f_manifest} {where_s} — the inventory must pin the document the verdict rests on, not only its neighbours"
        ));
    }

    if let Some(ref rd) = run_dir {
        let prefix = format!("{rd}/");
        let mut gone: Vec<String> = outcome
            .missing
            .iter()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        gone.sort();
        if !gone.is_empty() {
            errors.push(format!(
                "{report_path}: this run's own artifact(s) {} are absent at {rev} — a run must retain the evidence it claims, even when other listed paths have moved on",
                fmt_py_str_list_owned(&gone)
            ));
        }
    }

    errors
}

fn collect_claims(root: &Path) -> Vec<(String, String, Option<String>)> {
    let mut out = Vec::new();
    for rec in collect_proof_status(&root.join("skills"), root) {
        if let Some(ref proof) = rec.proof {
            if ADVANCING_TIERS.contains(&proof.as_str()) {
                let mission = rec.name.unwrap_or(rec.dir);
                out.push((mission, proof.clone(), rec.proof_evidence));
            }
        }
    }
    out
}

fn default_root(has_explicit_report: bool) -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if has_explicit_report {
        if let Some(git_top) = repo_root(&cwd) {
            return git_top;
        }
        if let Ok(explicit) = env::var("OPEN_FLEET_ROOT") {
            if !explicit.trim().is_empty() {
                return PathBuf::from(explicit);
            }
        }
        return find_catalog_root(&cwd).unwrap_or(cwd);
    }
    if cwd.join("skills").is_dir() {
        return cwd;
    }
    if let Ok(explicit) = env::var("OPEN_FLEET_ROOT") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    find_catalog_root(&cwd).unwrap_or(cwd)
}

fn print_help() {
    println!(
        "usage: run_report.py [-h] [--mission MISSION] [--tier TIER] [--base REV] [--root DIR] [--json] [report]\n\n\
         Check that a proof-tier advance is bound to artifacts, not a filename.\n\n\
         positional arguments:\n\
           report             one report to check (default: every claim)\n\n\
         options:\n\
           -h, --help         show this help message and exit\n\
           --mission MISSION  mission the report is claimed by (with `report`)\n\
           --tier TIER        tier claimed (with `report`)\n\
           --base REV         grading base (trusted remote-tracking ref or commit id on sound lanes)\n\
           --root DIR         repository root directory\n\
           --json             emit structured JSON output\n\n\
         exit 0 bound / 1 not bound / 2 could-not-run"
    );
}

struct CliParsed {
    report: Option<String>,
    mission: Option<String>,
    tier: Option<String>,
    base: Option<String>,
    root: Option<PathBuf>,
    json_out: bool,
    help: bool,
}

fn parse_cli(args: &[OsString]) -> Result<CliParsed, String> {
    let mut parsed = CliParsed {
        report: None,
        mission: None,
        tier: None,
        base: None,
        root: None,
        json_out: false,
        help: false,
    };
    let mut positional_only = false;
    let mut i = 0usize;
    while i < args.len() {
        let s = args[i].to_string_lossy();
        if !positional_only {
            if s == "--" {
                positional_only = true;
                i += 1;
                continue;
            }
            if s == "-h" || s == "--help" {
                parsed.help = true;
                return Ok(parsed);
            }
            if s == "--json" {
                parsed.json_out = true;
                i += 1;
                continue;
            }
            if s == "--mission" {
                if i + 1 >= args.len() {
                    return Err("argument --mission: expected one argument".to_string());
                }
                parsed.mission = Some(args[i + 1].to_string_lossy().into_owned());
                i += 2;
                continue;
            }
            if let Some(v) = s.strip_prefix("--mission=") {
                parsed.mission = Some(v.to_string());
                i += 1;
                continue;
            }
            if s == "--tier" {
                if i + 1 >= args.len() {
                    return Err("argument --tier: expected one argument".to_string());
                }
                parsed.tier = Some(args[i + 1].to_string_lossy().into_owned());
                i += 2;
                continue;
            }
            if let Some(v) = s.strip_prefix("--tier=") {
                parsed.tier = Some(v.to_string());
                i += 1;
                continue;
            }
            if s == "--base" {
                if i + 1 >= args.len() {
                    return Err("argument --base: expected one argument".to_string());
                }
                parsed.base = Some(args[i + 1].to_string_lossy().into_owned());
                i += 2;
                continue;
            }
            if let Some(v) = s.strip_prefix("--base=") {
                parsed.base = Some(v.to_string());
                i += 1;
                continue;
            }
            if s == "--root" {
                if i + 1 >= args.len() {
                    return Err("argument --root: expected one argument".to_string());
                }
                parsed.root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
                continue;
            }
            if let Some(v) = s.strip_prefix("--root=") {
                parsed.root = Some(PathBuf::from(v));
                i += 1;
                continue;
            }
            if s.starts_with('-') {
                return Err(format!("unrecognized arguments: {s}"));
            }
        }
        if parsed.report.is_some() {
            return Err(format!("unrecognized arguments: {s}"));
        }
        parsed.report = Some(s.into_owned());
        i += 1;
    }
    Ok(parsed)
}

pub fn run_raw(args: &[OsString]) -> i32 {
    let parsed = match parse_cli(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("run_report.py: error: {msg}");
            return 2;
        }
    };
    if parsed.help {
        print_help();
        return 0;
    }

    let root = parsed
        .root
        .unwrap_or_else(|| default_root(parsed.report.is_some()));

    let claims: Vec<(String, String, Option<String>)> = if let Some(ref report) = parsed.report {
        let (Some(mission), Some(tier)) = (parsed.mission.as_ref(), parsed.tier.as_ref()) else {
            eprintln!(
                "run_report.py: error: --mission and --tier are required with an explicit report"
            );
            return 2;
        };
        vec![(mission.clone(), tier.clone(), Some(report.clone()))]
    } else {
        let skills_dir = root.join("skills");
        if !skills_dir.is_dir() {
            eprintln!("skills/ not found at {}", skills_dir.display());
            return 2;
        }
        collect_claims(&root)
    };

    if let Some(refusal) = sound_lane_refusal(&root, parsed.base.as_deref()) {
        if parsed.json_out {
            let results: Vec<Value> = claims
                .iter()
                .map(|(m, t, ev)| {
                    let ev_s = ev.as_deref().unwrap_or("");
                    json!({
                        "mission": m,
                        "tier": t,
                        "evidence": ev,
                        "bound": false,
                        "errors": [format!("{ev_s}: {refusal}")],
                    })
                })
                .collect();
            let payload = json!({
                "ok": false,
                "refusal": refusal,
                "results": results,
            });
            println!(
                "{}",
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            );
        }
        eprintln!("run_report.py: {refusal}");
        return 2;
    }

    let mut failed = false;
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut json_results: Vec<Value> = Vec::new();

    for (mission, tier, evidence) in &claims {
        let ev_nonempty = evidence.as_deref().filter(|e| !e.is_empty());
        if let Some(ev) = ev_nonempty {
            if let Some(prev) = seen.get(ev) {
                let msg = format!(
                    "proof_evidence {ev} is already claimed by {prev}; one run report proves one mission's tier"
                );
                if !parsed.json_out {
                    println!("FAIL {mission} ({tier}) — {msg}");
                }
                json_results.push(json!({
                    "mission": mission,
                    "tier": tier,
                    "evidence": ev,
                    "bound": false,
                    "errors": [msg],
                }));
                failed = true;
                continue;
            }
            seen.insert(ev.to_string(), mission.clone());
        } else {
            if !parsed.json_out {
                println!("FAIL {mission} ({tier}) — no proof_evidence");
            }
            json_results.push(json!({
                "mission": mission,
                "tier": tier,
                "evidence": Value::Null,
                "bound": false,
                "errors": ["no proof_evidence"],
            }));
            failed = true;
            continue;
        }
        let ev = ev_nonempty.unwrap_or("");
        let errors = check_report(ev, mission, tier, &root, parsed.base.as_deref());
        if !errors.is_empty() {
            failed = true;
            if !parsed.json_out {
                println!("FAIL {mission} ({tier})");
                for error in &errors {
                    println!("   - {error}");
                }
            }
            json_results.push(json!({
                "mission": mission,
                "tier": tier,
                "evidence": ev,
                "bound": false,
                "errors": errors,
            }));
        } else {
            if !parsed.json_out {
                println!("bound {mission} ({tier}) — {ev}");
            }
            json_results.push(json!({
                "mission": mission,
                "tier": tier,
                "evidence": ev,
                "bound": true,
                "errors": [],
            }));
        }
    }

    if parsed.json_out {
        let payload = json!({
            "ok": !failed,
            "refusal": Value::Null,
            "results": json_results,
        });
        println!(
            "{}",
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
        );
    } else if claims.is_empty() {
        println!("no mission claims a tier above doctrine-only");
    }

    if failed {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn git_ok(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn test_executes_verifier_options_and_xoptions() {
        let tmp = TempDir::new().expect("tempdir");
        let repo = tmp.path();
        let v = "runtime/scripts/verify.py";
        let m = "m.json";

        for ok in [
            format!("python3 {v} --manifest {m}"),
            format!("python3 ./{v} --manifest {m}"),
            format!("/usr/bin/python3 -u {v} --contract-source c --manifest {m}"),
            format!("env FOO=1 python3 {v} --manifest={m}"),
            format!("python3 {v} --manifest other.json --manifest {m}"),
            format!("python3 -IB {v} --manifest {m}"),
            format!("python3 -OO -W ignore -X dev {v} --manifest {m}"),
            format!("python3 -uW ignore --check-hash-based-pycs always {v} --manifest {m}"),
            format!("python3 -X int_max_str_digits=0 -X utf8=1 -X utf8=2 -- {v} --manifest {m}"),
            format!("python3 -X int_max_str_digits= -X int_max_str_digits=+640 -X tracemalloc {v} --manifest {m}"),
            format!("python3 -X frozen_modules=off -X cpu_count=default -X gil=1 {v} --manifest {m}"),
            format!("python3.13t {v} --manifest {m}"),
            format!("./{v} --manifest {m}"),
        ] {
            assert!(executes_verifier(&ok, m, repo), "expected true for: {ok}");
        }

        for bad in [
            format!("echo {v} --manifest {m}"),
            format!("true # {v} --manifest {m}"),
            format!("python3 -cpass {v} --manifest {m}"),
            format!("python3 -ucpass {v} --manifest {m}"),
            format!("python3 -m mod {v} --manifest {m}"),
            format!("python3 -uV {v} --manifest {m}"),
            format!("python3 --help {v} --manifest {m}"),
            format!("python3 -X utf8=2 -X utf8=1 -- {v} --manifest {m}"),
            format!("python3 -X int_max_str_digits=1 {v} --manifest {m}"),
            format!("python3 -X int_max_str_digits {v} --manifest {m}"),
            format!("python3 -X tracemalloc=65536 {v} --manifest {m}"),
            format!("python3 -X cpu_count=0 {v} --manifest {m}"),
            format!("python3 -X gil=2 {v} --manifest {m}"),
            format!("python3 -X frozen_modules=bad {v} --manifest {m}"),
            format!("python3 {v} --manifest {m} --manifest other.json"),
            format!("python3 {v} --manifest {m} --manifest"),
            format!("python3 {v} --manifest {m} --help"),
            format!("python3 {v} --manifest {m} -h"),
            format!("python3 {v} --manifest {m} --he"),
            format!("python3 {v} --man {m}"),
            format!("PATH=/tmp/evil python3 {v} --manifest {m}"),
            format!("env PYTHONPATH=/tmp/evil python3 {v} --manifest {m}"),
            format!("LD_PRELOAD=/tmp/evil.so python3 {v} --manifest {m}"),
            format!("DYLD_INSERT_LIBRARIES=/tmp/e.dylib python3 {v} --manifest {m}"),
            format!("/tmp/python3 {v} --manifest {m}"),
            format!("/var/tmp/python3 {v} --manifest {m}"),
            format!("/dev/shm/python {v} --manifest {m}"),
            format!("./python3 {v} --manifest {m}"),
            format!("/usr/bin/../tmp/python3 {v} --manifest {m}"),
            format!("python-decoy {v} --manifest {m}"),
            format!("python3 /tmp/verify.py --manifest {m}"),
            format!("python3 shadow/{v} --manifest {m}"),
            format!("python3 ../../tmp/{v} --manifest {m}"),
        ] {
            assert!(
                !executes_verifier(&bad, m, repo),
                "expected false for: {bad}"
            );
        }
    }

    #[test]
    fn test_run_directory_rules() {
        let tmp = TempDir::new().expect("tempdir");
        let runs = tmp.path().join("docs/runs");
        fs::create_dir_all(runs.join("2026-09-14-map-iteration")).expect("mkdir");
        fs::create_dir_all(runs.join("2026-09-13-pin-it-266")).expect("mkdir");
        fs::create_dir_all(runs.join("2026-09-14-clean-sweep-tracker")).expect("mkdir");

        let r1 = runs.join("2026-09-14-map-it-selfrun.md");
        assert_eq!(
            run_directory(&r1, "map-it", tmp.path()).as_deref(),
            Some("docs/runs/2026-09-14-map-it-selfrun")
        );
        let r2 = runs.join("2026-09-13-pin-it-266-selfrun.md");
        assert_eq!(
            run_directory(&r2, "pin-it", tmp.path()).as_deref(),
            Some("docs/runs/2026-09-13-pin-it-266")
        );
        let r3 = runs.join("2026-09-14-clean-sweep-self-run.md");
        assert_eq!(
            run_directory(&r3, "clean-sweep", tmp.path()).as_deref(),
            Some("docs/runs/2026-09-14-clean-sweep-tracker")
        );
    }

    #[test]
    fn test_self_pinned_key_refusal_o33() {
        let tmp = TempDir::new().expect("tempdir");
        let repo = tmp.path();
        git_ok(repo, &["init", "-q", "-b", "trunk", "."]);
        git_ok(repo, &["config", "user.email", "t@example.com"]);
        git_ok(repo, &["config", "user.name", "t"]);
        fs::create_dir_all(repo.join(".orca")).expect("mkdir");
        fs::write(
            repo.join(".orca/dispatch-pubkey"),
            format!("{}\n", "ab".repeat(32)),
        )
        .expect("write");
        git_ok(repo, &["add", "-A"]);
        git_ok(repo, &["commit", "-qm", "self-pinned"]);
        let rev = git_ok(repo, &["rev-parse", "HEAD"]);

        let (at, why) = key_rev(&rev, repo, None);
        assert!(at.is_none(), "expected None, got {at:?}");
        assert!(why.contains("O-3.3"), "unexpected why: {why}");

        git_ok(repo, &["branch", "-f", "main", &rev]);
        let (at2, why2) = key_rev(&rev, repo, None);
        assert_eq!(at2.as_deref(), Some(rev.as_str()));
        assert!(why2.contains("the pin"), "unexpected why2: {why2}");

        // Off-base commit introducing its own key must not enforce when base carries none.
        git_ok(repo, &["checkout", "-q", "-b", "base-clean"]);
        fs::remove_file(repo.join(".orca/dispatch-pubkey")).expect("rm");
        git_ok(repo, &["add", "-A"]);
        git_ok(repo, &["commit", "-qm", "no key on base"]);
        let clean_base = git_ok(repo, &["rev-parse", "HEAD"]);
        git_ok(repo, &["checkout", "-q", "-b", "claim"]);
        fs::write(
            repo.join(".orca/dispatch-pubkey"),
            format!("{}\n", "cd".repeat(32)),
        )
        .expect("write");
        git_ok(repo, &["add", "-A"]);
        git_ok(repo, &["commit", "-qm", "claim adds key"]);
        let claim_rev = git_ok(repo, &["rev-parse", "HEAD"]);
        let (pub_k, at_k, why_k) = enforcement_key(&claim_rev, repo, Some(&clean_base));
        assert!(pub_k.is_none());
        assert_eq!(at_k.as_deref(), Some(clean_base.as_str()));
        assert!(why_k.contains("grading base"), "unexpected why_k: {why_k}");
    }

    #[test]
    fn test_wip_curve_validation_edges() {
        let tmp = TempDir::new().expect("tempdir");
        let repo = tmp.path();
        git_ok(repo, &["init", "-q", "-b", "main", "."]);
        git_ok(repo, &["config", "user.email", "t@example.com"]);
        git_ok(repo, &["config", "user.name", "t"]);
        fs::create_dir_all(repo.join("runtime")).expect("mkdir");
        fs::write(
            repo.join("runtime/evidence-manifest.md"),
            "- **Mutation units** (ship-it, absorb-it) — need a negative control.\n",
        )
        .expect("write");
        git_ok(repo, &["add", "-A"]);
        git_ok(repo, &["commit", "-qm", "policy"]);

        let row1 = "| wave=1 | builders=3 reviewers=1 | throughput=1.5/h | latency_median=12m | latency_max=40m | rework=0/3 | freshness=0 |";
        let row2 = "| wave=2 | builders=2 reviewers=1 | throughput=0.8/h | latency_median=20m | latency_max=55m | rework=1/2 | freshness=1 |";
        let sec = "## WIP-curve protocol row (mutating self-runs)";

        let ok_body = format!("RUN: mission=ship-it waves=2\n\n{sec}\n\n{row1}\n{row2}\n");
        assert!(wip_curve_errors(&ok_body, "ship-it", repo, "r.md", None, None).is_empty());
        assert!(wip_curve_errors("no rows", "review-it", repo, "r.md", None, None).is_empty());

        let dup_waves = format!("RUN: mission=ship-it waves=3 waves=1\n\n{sec}\n\n{row1}\n");
        let errs = wip_curve_errors(&dup_waves, "ship-it", repo, "r.md", None, None);
        assert!(errs.iter().any(|e| e.contains("waves= more than once")));

        let dup_cell = format!(
            "RUN: mission=ship-it waves=1\n\n{sec}\n\n{}\n",
            row1.replace("throughput=1.5/h", "throughput=TBD throughput=1")
        );
        let errs = wip_curve_errors(&dup_cell, "ship-it", repo, "r.md", None, None);
        assert!(errs
            .iter()
            .any(|e| e.contains("carries ['throughput'] more than once")));

        let missing_w2 = format!("RUN: mission=ship-it waves=2\n\n{sec}\n\n{row1}\n");
        let errs = wip_curve_errors(&missing_w2, "ship-it", repo, "r.md", None, None);
        assert!(errs
            .iter()
            .any(|e| e.contains("no WIP-curve row for wave(s) [2]")));

        let doubled_w1 =
            format!("RUN: mission=ship-it waves=2\n\n{sec}\n\n{row1}\n{row1}\n{row2}\n");
        let errs = wip_curve_errors(&doubled_w1, "ship-it", repo, "r.md", None, None);
        assert!(errs
            .iter()
            .any(|e| e.contains("wave(s) [1] carry more than one WIP-curve row")));

        let stray_w2 = format!("RUN: mission=ship-it waves=1\n\n{sec}\n\n{row1}\n{row2}\n");
        let errs = wip_curve_errors(&stray_w2, "ship-it", repo, "r.md", None, None);
        assert!(errs
            .iter()
            .any(|e| e.contains("wave(s) [2] outside the recorded waves 1..1")));

        let non_git = TempDir::new().expect("tempdir");
        assert!(
            wip_curve_errors("anything", "ship-it", non_git.path(), "r.md", None, None).is_empty()
        );
    }

    #[test]
    fn test_in_tree_and_symlink_interpreters_refused() {
        let root = Path::new("/opt/checkouts/open-fleet");
        assert!(!is_python_interpreter(
            "/opt/checkouts/open-fleet/python3",
            root
        ));
        assert!(!is_python_interpreter(
            "/opt/checkouts/open-fleet/.venv/bin/python3",
            root
        ));
        assert!(is_python_interpreter("/opt/checkouts/other/python3", root));
        assert!(is_python_interpreter("/usr/bin/python3", root));
        assert!(is_python_interpreter("python3", root));

        #[cfg(unix)]
        {
            let tmp = TempDir::new().expect("tempdir");
            let real = tmp.path().join("real-tree");
            let alias = tmp.path().join("alias");
            fs::create_dir_all(&real).expect("mkdir");
            fs::create_dir_all(&alias).expect("mkdir");
            std::os::unix::fs::symlink(&real, alias.join("linked")).expect("symlink");
            let tok = alias.join("linked/python3");
            assert!(!is_python_interpreter(&tok.to_string_lossy(), &real));
        }
    }
}
