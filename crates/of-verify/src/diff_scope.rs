//! Native Rust port of `runtime/scripts/diff_scope.py`:
//! fail-loud review-lens scope classification, pre-dispatch glob overlap detection,
//! and in-memory 3-way merge prediction via `git merge-tree --write-tree`.

use crate::base64_codec::{push_json_bytes_surrogate, push_json_str_ascii};
use of_common::gitexec::{
    base_commit, driver_blanks, run_git_repo, sound_lane, Custody, NO_SUBMODULE_CHILD,
};
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const EXIT_OK: i32 = 0;
pub const EXIT_PREDICTED_CONFLICT: i32 = 1;
pub const EXIT_SCOPE_ERROR: i32 = 2;

const CONTENT_CAP: usize = 256 * 1024;

pub const FLAGS: &[&str] = &[
    "FRONTEND",
    "BACKEND",
    "PROMPTS",
    "TESTS",
    "DOCS",
    "CONFIG",
    "MIGRATIONS",
    "API",
    "AUTH",
    "SECURITY",
    "A11Y",
    "PERF",
];

const FRONTEND_EXT: &[&str] = &[
    ".css", ".scss", ".less", ".sass", ".pcss", ".styl", ".tsx", ".jsx", ".vue", ".svelte",
    ".astro", ".erb", ".haml", ".slim", ".hbs", ".ejs", ".html", ".htm",
];
const BACKEND_EXT: &[&str] = &[
    ".rb", ".py", ".go", ".rs", ".java", ".kt", ".php", ".ex", ".exs", ".cs", ".scala", ".c",
    ".cc", ".cpp", ".h", ".hpp", ".swift", ".pl", ".ts", ".js", ".mjs", ".cjs", ".mts", ".cts",
];
const DOC_EXT: &[&str] = &[".md", ".rst", ".adoc", ".txt"];
const CONFIG_EXT: &[&str] = &[
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
];
const CONFIG_NAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "gemfile",
    "gemfile.lock",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "dockerfile",
    "makefile",
    "poetry.lock",
];

fn path_rules() -> &'static Vec<(&'static str, Regex)> {
    static RULES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            (
                "FRONTEND",
                Regex::new(r"(^|/)(components|views|templates|styles|css|stylesheets)/")
                    .expect("regex"),
            ),
            (
                "FRONTEND",
                Regex::new(r"(^|/)(tailwind|postcss)\.config\.").expect("regex"),
            ),
            (
                "PROMPTS",
                Regex::new(r"prompt|(^|/)(skills|playbooks)/|(^|/)(SKILL|AGENTS)\.md$|\.prompt$")
                    .expect("regex"),
            ),
            (
                "TESTS",
                Regex::new(
                    r"\.(test|spec)\.|_(test|spec)\.|(^|/)test_[^/]*$|(^|/)(tests?|spec|__tests__|cypress|e2e)/",
                )
                .expect("regex"),
            ),
            ("DOCS", Regex::new(r"(^|/)docs?/").expect("regex")),
            (
                "DOCS",
                Regex::new(r"^docs/assets/badges/(tests|missions)\.json$").expect("regex"),
            ),
            (
                "CONFIG",
                Regex::new(r"(^|/)\.github/|(^|/)\.circleci/|(^|/)ci/").expect("regex"),
            ),
            (
                "MIGRATIONS",
                Regex::new(
                    r"(^|/)(db/migrate|migrations|alembic|prisma/migrations|db/data|data_migrations)/",
                )
                .expect("regex"),
            ),
            (
                "API",
                Regex::new(
                    r"(^|/)api/|controller|route|endpoint|handler|\.(graphql|gql)$|(^|/)(openapi|swagger)\.",
                )
                .expect("regex"),
            ),
            (
                "AUTH",
                Regex::new(
                    r"auth|session|jwt|oauth|permission|role|login|logout|password|credential",
                )
                .expect("regex"),
            ),
            (
                "SECURITY",
                Regex::new(r"security|crypto|secret|sanitiz|escape|csrf|xss|redact")
                    .expect("regex"),
            ),
            ("A11Y", Regex::new(r"a11y|accessib|aria").expect("regex")),
            (
                "PERF",
                Regex::new(r"bench|perf|cache|throttl|index").expect("regex"),
            ),
        ]
    })
}

fn content_rules() -> &'static Vec<(&'static str, Regex)> {
    static RULES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            (
                "PROMPTS",
                Regex::new(r#"You are an? |system prompt|<system>|role\s*:\s*["']system"#)
                    .expect("regex"),
            ),
            (
                "API",
                Regex::new(
                    r"@app\.route|@router\.|app\.(get|post|put|delete)\(|Route\(|http\.HandleFunc",
                )
                .expect("regex"),
            ),
            (
                "AUTH",
                Regex::new(r"authenticate|authorize|Set-Cookie|Bearer |session\[|current_user")
                    .expect("regex"),
            ),
            (
                "SECURITY",
                Regex::new(
                    r"subprocess\.|shell=True|os\.system|innerHTML|pickle\.loads|verify=False|dangerouslySetInnerHTML",
                )
                .expect("regex"),
            ),
            (
                "A11Y",
                Regex::new(r"aria-|role=|alt=|tabindex|tabIndex|focus-visible|<button|<img")
                    .expect("regex"),
            ),
            (
                "PERF",
                Regex::new(
                    r"useMemo|useCallback|lru_cache|perf_counter|benchmark|N\+1|EXPLAIN |createIndex|add_index",
                )
                .expect("regex"),
            ),
        ]
    })
}

fn merge_stage_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(r"(?-u)^[0-9]{6}\s+[0-9a-f]{40,64}\s+[123]\t(.+)$").expect("regex")
    })
}

fn merge_conflict_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(
            r"(?-u)^CONFLICT\s*\([^)]+\):\s*(?:Merge conflict in\s+)?(.+?)(?:\s+deleted in .+|$)",
        )
        .expect("regex")
    })
}

#[derive(Debug, Clone)]
pub struct ScopeError {
    pub message: String,
    pub kind: &'static str,
    pub resolved: Option<String>,
}

impl ScopeError {
    fn new(message: impl Into<String>, kind: &'static str, resolved: Option<String>) -> Self {
        Self {
            message: message.into(),
            kind,
            resolved,
        }
    }
}

pub fn shell_comment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let u = ch as u32;
        if ch == '\r' || ch == '\n' || u < 0x20 || u == 0x7f {
            out.push_str(&format!("\\x{:02x}", u));
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn shell_comment_bytes(raw: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(raw);
    shell_comment(&lossy)
}

pub fn resolve_base(repo: &Path, base: Option<&str>) -> Result<(String, String), ScopeError> {
    let res = match base_commit(repo, base) {
        Ok(r) => r,
        Err(why) => {
            let shown = base.unwrap_or("origin/HEAD");
            eprintln!("diff_scope: base {shown:?} {why}");
            return Err(ScopeError::new(shown, "no_base", None));
        }
    };
    if let Some(local) = res.local {
        if let Some(lane) = sound_lane() {
            let prefix = &res.commit[..res.commit.len().min(12)];
            eprintln!(
                "diff_scope: {lane} claims a sound lane, but base {:?} is {local} ({prefix}), not a remote-tracking ref or a full commit id — name origin/<branch> or a full commit id (W3-07)",
                res.shown
            );
            return Err(ScopeError::new(
                base.unwrap_or(&res.shown).to_string(),
                "no_base",
                None,
            ));
        }
        let prefix = &res.commit[..res.commit.len().min(12)];
        eprintln!(
            "diff_scope: NOTE — base {:?} is {local} ({prefix}), not a remote-tracking ref or a full commit id, so advisory; --base origin/<branch> (or a full commit id) is one the change under check cannot move",
            res.shown
        );
    }
    Ok((res.commit, res.shown))
}

fn absorb_nul_paths(
    out: Result<of_common::gitexec::GitOutput, String>,
    phase: &str,
    resolved: &str,
    names: &mut BTreeSet<Vec<u8>>,
) -> Result<(), ScopeError> {
    let git_out = match out {
        Ok(o) if o.code == 0 => o,
        Ok(_) => {
            return Err(ScopeError::new(
                format!("{phase} acquisition failed"),
                "diff_failed",
                Some(resolved.to_string()),
            ))
        }
        Err(_) => {
            return Err(ScopeError::new(
                format!("{phase} acquisition failed"),
                "diff_failed",
                Some(resolved.to_string()),
            ))
        }
    };
    for part in git_out.stdout.split(|&b| b == 0) {
        if !part.is_empty() {
            names.insert(part.to_vec());
        }
    }
    Ok(())
}

pub fn changed_files(repo: &Path, base_commit_sha: &str) -> Result<Vec<Vec<u8>>, ScopeError> {
    let blanks = driver_blanks(repo)
        .map_err(|e| ScopeError::new(e, "diff_failed", Some(base_commit_sha.to_string())))?;

    let mut names: BTreeSet<Vec<u8>> = BTreeSet::new();
    let range = format!("{base_commit_sha}...HEAD");
    let committed = run_git_repo(
        repo,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "-z",
            "--name-only",
            &range,
            "--",
        ],
        &blanks,
    );
    absorb_nul_paths(committed, "committed diff", base_commit_sha, &mut names)?;

    let custody = Custody::open(repo).map_err(|err| {
        ScopeError::new(
            format!("working-tree diff acquisition failed: {err}"),
            "diff_failed",
            Some(base_commit_sha.to_string()),
        )
    })?;

    let wt_args: Vec<OsString> = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "-z",
        "--name-only",
        NO_SUBMODULE_CHILD,
        "HEAD",
        "--",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let worktree = custody.run(&wt_args, &blanks);
    absorb_nul_paths(worktree, "working-tree diff", base_commit_sha, &mut names)?;

    let untracked_args: Vec<OsString> = ["ls-files", "-z", "--others", "--exclude-standard"]
        .iter()
        .map(OsString::from)
        .collect();
    let untracked = custody.run(&untracked_args, &[]);
    absorb_nul_paths(
        untracked,
        "untracked enumeration",
        base_commit_sha,
        &mut names,
    )?;

    Ok(names.into_iter().collect())
}

#[cfg(unix)]
fn join_raw_path(repo: &Path, raw: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    repo.join(OsStr::from_bytes(raw))
}

#[cfg(not(unix))]
fn join_raw_path(repo: &Path, raw: &[u8]) -> PathBuf {
    repo.join(String::from_utf8_lossy(raw).as_ref())
}

fn read_worktree(repo: &Path, raw_path: &[u8]) -> String {
    let p = join_raw_path(repo, raw_path);
    if !p.is_file() {
        return String::new();
    }
    let Ok(f) = File::open(&p) else {
        return String::new();
    };
    let mut buf = Vec::new();
    let mut limited = f.take(CONTENT_CAP as u64);
    if limited.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn py_suffix(low: &str) -> String {
    let name = low.rsplit('/').next().unwrap_or(low);
    // Python Path.suffix: leading dot on a dotfile like ".env" is NOT a suffix,
    // while ".hidden.ts" has suffix ".ts".
    let trimmed = name.trim_start_matches('.');
    match trimmed.rfind('.') {
        Some(idx) if idx > 0 => trimmed[idx..].to_string(),
        _ => String::new(),
    }
}

pub fn classify(repo: &Path, raw_path: &[u8]) -> BTreeSet<&'static str> {
    let path_str = String::from_utf8_lossy(raw_path);
    let low = path_str.to_lowercase();
    let suffix = py_suffix(&low);
    let name = low.rsplit('/').next().unwrap_or(&low);

    let mut hits: BTreeSet<&'static str> = BTreeSet::new();
    if FRONTEND_EXT.contains(&suffix.as_str()) {
        hits.insert("FRONTEND");
    }
    if DOC_EXT.contains(&suffix.as_str()) {
        hits.insert("DOCS");
    }
    if CONFIG_EXT.contains(&suffix.as_str())
        || CONFIG_NAMES.contains(&name)
        || name.starts_with("dockerfile")
    {
        hits.insert("CONFIG");
    }
    for (flag, re) in path_rules() {
        if re.is_match(&low) {
            hits.insert(*flag);
        }
    }
    if !hits.contains("FRONTEND") && BACKEND_EXT.contains(&suffix.as_str()) {
        hits.insert("BACKEND");
    }

    let text = read_worktree(repo, raw_path);
    if !text.is_empty() {
        for (flag, re) in content_rules() {
            if !hits.contains(*flag) && re.is_match(&text) {
                hits.insert(*flag);
            }
        }
    }
    hits
}

pub struct ScopeResult {
    pub flags: BTreeMap<&'static str, bool>,
    pub unmatched: Vec<Vec<u8>>,
    pub shown_base: String,
}

pub fn compute_scope(repo: &Path, base: Option<&str>) -> Result<ScopeResult, ScopeError> {
    let (commit, shown) = resolve_base(repo, base)?;
    let mut flags: BTreeMap<&'static str, bool> = FLAGS.iter().map(|&f| (f, false)).collect();
    let mut unmatched = Vec::new();
    for path in changed_files(repo, &commit)? {
        let hits = classify(repo, &path);
        if hits.is_empty() {
            unmatched.push(path);
            continue;
        }
        for f in hits {
            flags.insert(f, true);
        }
    }
    Ok(ScopeResult {
        flags,
        unmatched,
        shown_base: shown,
    })
}

pub fn scope_to_json(repo: &Path, base: Option<&str>, strict: bool) -> (i32, Value) {
    match compute_scope(repo, base) {
        Err(err) => {
            let mut empty = Map::new();
            for &f in FLAGS {
                empty.insert(f.to_string(), Value::Bool(false));
            }
            let base_field = if err.kind == "no_base" {
                Value::String(err.message.clone())
            } else {
                err.resolved
                    .clone()
                    .or_else(|| base.map(|s| s.to_string()))
                    .map(Value::String)
                    .unwrap_or(Value::Null)
            };
            (
                EXIT_SCOPE_ERROR,
                json!({
                    "flags": Value::Object(empty),
                    "error": err.kind,
                    "base": base_field,
                    "unmatched": [],
                }),
            )
        }
        Ok(res) => {
            let any_true = res.flags.values().any(|&v| v);
            let nothing_matched = !res.unmatched.is_empty() && !any_true;
            let err = if nothing_matched || (!res.unmatched.is_empty() && strict) {
                Some("unmatched")
            } else {
                None
            };
            let mut fobj = Map::new();
            for &f in FLAGS {
                fobj.insert(
                    f.to_string(),
                    Value::Bool(*res.flags.get(f).unwrap_or(&false)),
                );
            }
            let cap = res.unmatched.len().min(50);
            let unm: Vec<Value> = res.unmatched[..cap]
                .iter()
                .map(|b| Value::String(String::from_utf8_lossy(b).into_owned()))
                .collect();
            let code = if err.is_some() {
                EXIT_SCOPE_ERROR
            } else {
                EXIT_OK
            };
            (
                code,
                json!({
                    "flags": Value::Object(fobj),
                    "error": err,
                    "base": res.shown_base,
                    "unmatched": unm,
                }),
            )
        }
    }
}

// --- fnmatchcase + glob intersection for --overlap ---------------------------------------------

fn fnmatchcase_chars(name: &[char], pat: &[char]) -> bool {
    let (n, m) = (name.len(), pat.len());
    let mut stack = vec![(0usize, 0usize)];
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    seen.insert((0, 0));

    while let Some((ni, pi)) = stack.pop() {
        if pi == m {
            if ni == n {
                return true;
            }
            continue;
        }
        match pat[pi] {
            '*' => {
                if seen.insert((ni, pi + 1)) {
                    stack.push((ni, pi + 1));
                }
                if ni < n && seen.insert((ni + 1, pi)) {
                    stack.push((ni + 1, pi));
                }
            }
            '?' => {
                if ni < n && seen.insert((ni + 1, pi + 1)) {
                    stack.push((ni + 1, pi + 1));
                }
            }
            '[' => {
                // Find closing ']' per Python fnmatch.translate semantics
                let mut j = pi + 1;
                if j < m && pat[j] == '!' {
                    j += 1;
                }
                if j < m && pat[j] == ']' {
                    j += 1;
                }
                while j < m && pat[j] != ']' {
                    j += 1;
                }
                if j >= m {
                    // Literal '['
                    if ni < n && name[ni] == '[' && seen.insert((ni + 1, pi + 1)) {
                        stack.push((ni + 1, pi + 1));
                    }
                } else if ni < n {
                    let ch = name[ni];
                    let neg = pat[pi + 1] == '!';
                    let start = if neg { pi + 2 } else { pi + 1 };
                    let slice = &pat[start..j];
                    let mut matched = false;
                    let mut k = 0;
                    while k < slice.len() {
                        if k + 2 < slice.len() && slice[k + 1] == '-' {
                            if ch >= slice[k] && ch <= slice[k + 2] {
                                matched = true;
                            }
                            k += 3;
                        } else {
                            if ch == slice[k] {
                                matched = true;
                            }
                            k += 1;
                        }
                    }
                    if matched != neg && seen.insert((ni + 1, j + 1)) {
                        stack.push((ni + 1, j + 1));
                    }
                }
            }
            lit => {
                if ni < n && name[ni] == lit && seen.insert((ni + 1, pi + 1)) {
                    stack.push((ni + 1, pi + 1));
                }
            }
        }
    }
    false
}

pub fn is_test_path(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    path_rules()
        .iter()
        .any(|(flag, re)| *flag == "TESTS" && re.is_match(&low))
}

pub fn fnmatchcase(name: &str, pat: &str) -> bool {
    let nc: Vec<char> = name.chars().collect();
    let pc: Vec<char> = pat.chars().collect();
    fnmatchcase_chars(&nc, &pc)
}

fn strip_dot_slash(pattern: &str) -> &str {
    let mut p = pattern.trim();
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p
}

pub fn glob_intersects(pa: &str, pb: &str) -> bool {
    let a = strip_dot_slash(pa);
    let b = strip_dot_slash(pb);
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b || fnmatchcase(a, b) || fnmatchcase(b, a) {
        return true;
    }
    let a_dir = format!("{}/", a.trim_end_matches('/'));
    let b_dir = format!("{}/", b.trim_end_matches('/'));
    if a.starts_with(&b_dir) || b.starts_with(&a_dir) {
        return true;
    }

    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    let (la, lb) = (ac.len(), bc.len());
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut stack = vec![(0usize, 0usize)];
    seen.insert((0, 0));

    let starts_with_at = |arr: &[char], idx: usize, needle: &[char]| -> bool {
        idx + needle.len() <= arr.len() && &arr[idx..idx + needle.len()] == needle
    };

    while let Some((i, j)) = stack.pop() {
        if i == la && j == lb {
            return true;
        }
        let mut nxt: Vec<(usize, usize)> = Vec::new();
        if starts_with_at(&ac, i, &['/', '*', '*', '/']) {
            nxt.push((i + 3, j));
        }
        if i == 0 && starts_with_at(&ac, 0, &['*', '*', '/']) {
            nxt.push((i + 3, j));
        }
        if starts_with_at(&bc, j, &['/', '*', '*', '/']) {
            nxt.push((i, j + 3));
        }
        if j == 0 && starts_with_at(&bc, 0, &['*', '*', '/']) {
            nxt.push((i, j + 3));
        }
        if i < la && ac[i] == '*' {
            let is_globstar = (i + 1 < la && ac[i + 1] == '*') || (i > 0 && ac[i - 1] == '*');
            nxt.push((i + 1, j));
            if j < lb && (bc[j] != '/' || is_globstar) {
                nxt.push((i, j + 1));
            }
        }
        if j < lb && bc[j] == '*' {
            let is_globstar = (j + 1 < lb && bc[j + 1] == '*') || (j > 0 && bc[j - 1] == '*');
            nxt.push((i, j + 1));
            if i < la && (ac[i] != '/' || is_globstar) {
                nxt.push((i + 1, j));
            }
        }
        if i < la && j < lb {
            let (ca, cb) = (ac[i], bc[j]);
            if ca == cb || (ca == '?' && cb != '/') || (cb == '?' && ca != '/') {
                nxt.push((i + 1, j + 1));
            }
        }
        for state in nxt {
            if seen.insert(state) {
                stack.push(state);
            }
        }
    }
    false
}

struct OverlapUnit {
    id: String,
    scope: Vec<String>,
}

fn normalize_overlap_units(raw: &Value) -> Result<Vec<OverlapUnit>, ScopeError> {
    let items_val = if let Some(obj) = raw.as_object() {
        obj.get("units")
    } else {
        Some(raw)
    };
    let Some(items) = items_val.and_then(|v| v.as_array()) else {
        return Err(ScopeError::new(
            "overlap spec must be a non-empty list or {units: [...]}",
            "invalid_overlap",
            None,
        ));
    };
    if items.is_empty() {
        return Err(ScopeError::new(
            "overlap spec must be a non-empty list or {units: [...]}",
            "invalid_overlap",
            None,
        ));
    }
    let mut units = Vec::with_capacity(items.len());
    let mut seen: HashSet<String> = HashSet::new();
    for (idx, item) in items.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            return Err(ScopeError::new(
                format!("units[{idx}] must be an object"),
                "invalid_overlap",
                None,
            ));
        };
        let Some(uid) = obj.get("id").and_then(|v| v.as_str()) else {
            return Err(ScopeError::new(
                format!("units[{idx}].id must be a non-empty string"),
                "invalid_overlap",
                None,
            ));
        };
        if uid.trim().is_empty() {
            return Err(ScopeError::new(
                format!("units[{idx}].id must be a non-empty string"),
                "invalid_overlap",
                None,
            ));
        }
        if !seen.insert(uid.to_string()) {
            return Err(ScopeError::new(
                format!("duplicate unit id {uid:?}"),
                "invalid_overlap",
                None,
            ));
        }
        let Some(pats) = obj.get("scope").and_then(|v| v.as_array()) else {
            return Err(ScopeError::new(
                format!("units[{idx}].scope must be a non-empty list of globs/paths"),
                "invalid_overlap",
                None,
            ));
        };
        if pats.is_empty() {
            return Err(ScopeError::new(
                format!("units[{idx}].scope must be a non-empty list of globs/paths"),
                "invalid_overlap",
                None,
            ));
        }
        let mut scope = Vec::with_capacity(pats.len());
        for p in pats {
            let Some(ps) = p.as_str() else {
                return Err(ScopeError::new(
                    format!("units[{idx}].scope must be a non-empty list of globs/paths"),
                    "invalid_overlap",
                    None,
                ));
            };
            if ps.trim().is_empty() {
                return Err(ScopeError::new(
                    format!("units[{idx}].scope must be a non-empty list of globs/paths"),
                    "invalid_overlap",
                    None,
                ));
            }
            scope.push(ps.trim().to_string());
        }
        units.push(OverlapUnit {
            id: uid.trim().to_string(),
            scope,
        });
    }
    Ok(units)
}

fn tracked_files(repo: &Path) -> Result<Vec<String>, ScopeError> {
    let out = run_git_repo(repo, &["ls-files", "-z"], &[]).map_err(|_| {
        ScopeError::new(
            format!("git ls-files failed in {}", repo.display()),
            "diff_failed",
            None,
        )
    })?;
    if out.code != 0 {
        return Err(ScopeError::new(
            format!("git ls-files failed in {}", repo.display()),
            "diff_failed",
            None,
        ));
    }
    let mut files: Vec<String> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    files.sort();
    Ok(files)
}

struct OverlapItem {
    blocker: String,
    blocked: String,
    shared: Vec<String>,
}

type OverlapResult = (Vec<OverlapItem>, BTreeMap<String, Vec<String>>);

fn detect_scope_overlaps(raw: &Value, tracked: &[String]) -> Result<OverlapResult, ScopeError> {
    let normalized = normalize_overlap_units(raw)?;
    let mut overlaps = Vec::new();
    let mut deps_by_unit: BTreeMap<String, Vec<String>> = normalized
        .iter()
        .map(|u| (u.id.clone(), Vec::new()))
        .collect();
    for i in 0..normalized.len() {
        let ua = &normalized[i];
        for ub in &normalized[i + 1..] {
            let mut shared: BTreeSet<String> = BTreeSet::new();
            for fpath in tracked {
                let ma = ua.scope.iter().any(|pa| fnmatchcase(fpath, pa));
                let mb = ub.scope.iter().any(|pb| fnmatchcase(fpath, pb));
                if ma && mb {
                    shared.insert(fpath.clone());
                }
            }
            for pa in &ua.scope {
                for pb in &ub.scope {
                    if glob_intersects(pa, pb) {
                        if pa == pb {
                            shared.insert(pa.clone());
                        } else {
                            shared.insert(format!("{pa} & {pb}"));
                        }
                    }
                }
            }
            if !shared.is_empty() {
                overlaps.push(OverlapItem {
                    blocker: ua.id.clone(),
                    blocked: ub.id.clone(),
                    shared: shared.into_iter().collect(),
                });
                let entry = deps_by_unit.entry(ub.id.clone()).or_default();
                if !entry.contains(&ua.id) {
                    entry.push(ua.id.clone());
                }
            }
        }
    }
    Ok((overlaps, deps_by_unit))
}

// --- predict-merge (#590) ----------------------------------------------------------------------

pub struct MergePrediction {
    pub clean: bool,
    pub tree_oid: Option<String>,
    pub conflicts: Vec<Vec<u8>>,
}

impl MergePrediction {
    pub fn to_json_string(&self) -> String {
        let mut out = String::from("{\"clean\": ");
        out.push_str(if self.clean { "true" } else { "false" });
        out.push_str(", \"tree_oid\": ");
        match &self.tree_oid {
            Some(oid) => push_json_str_ascii(&mut out, oid),
            None => out.push_str("null"),
        }
        out.push_str(", \"conflicts\": [");
        for (i, c) in self.conflicts.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            push_json_bytes_surrogate(&mut out, c);
        }
        out.push_str("]}");
        out
    }
}

pub fn predict_merge(repo: &Path, base: &str, branch: &str) -> Result<MergePrediction, ScopeError> {
    let mut shas: Vec<String> = Vec::with_capacity(2);
    for (label, rref) in [("base", base), ("branch", branch)] {
        if rref.is_empty() || rref.starts_with('-') {
            return Err(ScopeError::new(
                format!(
                    "predict-merge {label} {rref:?} does not resolve to a commit in {} by its exact name: is empty or option-shaped",
                    repo.display()
                ),
                "no_base",
                None,
            ));
        }
        let res = base_commit(repo, Some(rref)).map_err(|why| {
            ScopeError::new(
                format!(
                    "predict-merge {label} {rref:?} does not resolve to a commit in {} by its exact name: {why}",
                    repo.display()
                ),
                "no_base",
                None,
            )
        })?;
        if let Some(local) = res.local {
            let prefix = &res.commit[..res.commit.len().min(12)];
            if let Some(lane) = sound_lane() {
                return Err(ScopeError::new(
                    format!(
                        "predict-merge: {lane} claims a sound lane, but {label} {:?} is {local} ({prefix}), not a remote-tracking ref or a full commit id (W3-07)",
                        res.shown
                    ),
                    "no_base",
                    None,
                ));
            }
            eprintln!(
                "diff_scope: NOTE — predict-merge {label} {:?} is {local} ({prefix}), not a remote-tracking ref or a full commit id, so advisory",
                res.shown
            );
        }
        shas.push(res.commit);
    }

    let blanks = driver_blanks(repo).map_err(|e| ScopeError::new(e, "diff_failed", None))?;
    let custody = Custody::open_with(repo, false, true)
        .map_err(|err| ScopeError::new(format!("predict-merge: {err}"), "diff_failed", None))?;

    let mt_args: Vec<OsString> = vec![
        OsString::from("-c"),
        OsString::from("core.quotePath=false"),
        OsString::from("merge-tree"),
        OsString::from("--write-tree"),
        OsString::from(&shas[0]),
        OsString::from(&shas[1]),
    ];
    let run_res = custody.run(&mt_args, &blanks).ok();

    if let Some(ref r) = run_res {
        if r.code == 0 {
            let text = String::from_utf8_lossy(&r.stdout);
            let tree_oid = text
                .lines()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .map(|s| s.to_string());
            return Ok(MergePrediction {
                clean: true,
                tree_oid,
                conflicts: Vec::new(),
            });
        }
        if r.code == 1 {
            let mut conflicts: BTreeSet<Vec<u8>> = BTreeSet::new();
            for raw_line in r.stdout.split(|&b| b == b'\n') {
                let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
                if let Some(caps) = merge_stage_re().captures(line) {
                    if let Some(m) = caps.get(1) {
                        conflicts.insert(trim_ascii_bytes(m.as_bytes()).to_vec());
                    }
                    continue;
                }
                if let Some(caps) = merge_conflict_re().captures(line) {
                    if let Some(m) = caps.get(1) {
                        conflicts.insert(trim_ascii_bytes(m.as_bytes()).to_vec());
                    }
                }
            }
            return Ok(MergePrediction {
                clean: false,
                tree_oid: None,
                conflicts: conflicts.into_iter().collect(),
            });
        }
    }

    let mb_ok = run_git_repo(repo, &["merge-base", &shas[0], &shas[1]], &[])
        .ok()
        .map(|o| o.code == 0 && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    if !mb_ok {
        return Err(ScopeError::new(
            format!("predict-merge: {base:?} and {branch:?} share no merge base"),
            "no_base",
            None,
        ));
    }
    let tail = if let Some(ref r) = run_res {
        let src = if !r.stderr.is_empty() {
            String::from_utf8_lossy(&r.stderr)
        } else {
            String::from_utf8_lossy(&r.stdout)
        };
        let last = src
            .trim()
            .lines()
            .last()
            .map(|l| l.chars().take(200).collect::<String>())
            .unwrap_or_else(|| "no output".to_string());
        format!(" (exit {}: {last})", r.code)
    } else {
        String::new()
    };
    Err(ScopeError::new(
        format!(
            "predict-merge: `git merge-tree --write-tree` failed in {}{tail}; predicting a merge needs git >= 2.38 — the classic merge-tree form cannot tell a clean merge from a conflict, so no prediction is made",
            repo.display()
        ),
        "diff_failed",
        None,
    ))
}

fn trim_ascii_bytes(mut b: &[u8]) -> &[u8] {
    while let Some(&first) = b.first() {
        if first.is_ascii_whitespace() {
            b = &b[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = b.last() {
        if last.is_ascii_whitespace() {
            b = &b[..b.len() - 1];
        } else {
            break;
        }
    }
    b
}

// --- CLI entry point ---------------------------------------------------------------------------

pub struct DiffScopeArgs {
    pub base: Option<String>,
    pub repo: PathBuf,
    pub strict: bool,
    pub overlap: Option<PathBuf>,
    pub predict_merge: Option<(String, String)>,
    pub json: bool,
}

pub fn run_cli(args: &DiffScopeArgs) -> i32 {
    if let Some((base_ref, branch_ref)) = &args.predict_merge {
        match predict_merge(&args.repo, base_ref, branch_ref) {
            Ok(pred) => {
                println!("{}", pred.to_json_string());
                return if pred.clean {
                    EXIT_OK
                } else {
                    EXIT_PREDICTED_CONFLICT
                };
            }
            Err(err) => {
                if args.json {
                    let payload = json!({
                        "clean": Value::Null,
                        "tree_oid": Value::Null,
                        "conflicts": [],
                        "error": err.kind,
                        "detail": err.message,
                    });
                    println!(
                        "{}",
                        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("SCOPE_ERROR={}", err.kind);
                    println!("# {}", shell_comment(&err.message));
                }
                return EXIT_SCOPE_ERROR;
            }
        }
    }

    if let Some(overlap_path) = &args.overlap {
        let parsed: Result<Value, ScopeError> = fs::read_to_string(overlap_path)
            .map_err(|e| {
                ScopeError::new(
                    format!("cannot read overlap spec {}: {e}", overlap_path.display()),
                    "invalid_overlap",
                    None,
                )
            })
            .and_then(|s| {
                serde_json::from_str(&s).map_err(|e| {
                    ScopeError::new(
                        format!("cannot read overlap spec {}: {e}", overlap_path.display()),
                        "invalid_overlap",
                        None,
                    )
                })
            });
        let result = parsed.and_then(|raw| {
            let tracked = tracked_files(&args.repo)?;
            detect_scope_overlaps(&raw, &tracked)
        });
        match result {
            Err(err) => {
                if args.json {
                    let payload = json!({
                        "overlaps": [],
                        "deps": {},
                        "error": err.kind,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("SCOPE_ERROR={}", err.kind);
                    println!("# {}", shell_comment(&err.message));
                }
                return EXIT_SCOPE_ERROR;
            }
            Ok((overlaps, deps)) => {
                if args.json {
                    let ov_json: Vec<Value> = overlaps
                        .iter()
                        .map(|o| {
                            json!({
                                "blocker": o.blocker,
                                "blocked": o.blocked,
                                "shared": o.shared,
                            })
                        })
                        .collect();
                    let payload = json!({
                        "overlaps": ov_json,
                        "deps": deps,
                        "error": Value::Null,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("OVERLAP_COUNT={}", overlaps.len());
                    for item in &overlaps {
                        let shared = item.shared.join(", ");
                        println!(
                            "# overlap: {} -> {} ({})",
                            shell_comment(&item.blocker),
                            shell_comment(&item.blocked),
                            shell_comment(&shared)
                        );
                    }
                }
                return EXIT_OK;
            }
        }
    }

    match compute_scope(&args.repo, args.base.as_deref()) {
        Err(err) => {
            if args.json {
                let mut empty = Map::new();
                for &f in FLAGS {
                    empty.insert(f.to_string(), Value::Bool(false));
                }
                let base_val = if err.kind == "no_base" {
                    Value::String(err.message.clone())
                } else {
                    err.resolved
                        .clone()
                        .or_else(|| args.base.clone())
                        .map(Value::String)
                        .unwrap_or(Value::Null)
                };
                let payload = json!({
                    "flags": Value::Object(empty),
                    "error": err.kind,
                    "base": base_val,
                    "unmatched": [],
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                for &f in FLAGS {
                    println!("SCOPE_{f}=false");
                }
                println!("SCOPE_ERROR={}", err.kind);
                if err.kind == "no_base" {
                    println!(
                        "# base ref '{}' is not resolvable — shallow checkout or missing fetch. Run: git fetch origin",
                        shell_comment(&err.message)
                    );
                } else {
                    println!(
                        "# {}; no scope verdict is available",
                        shell_comment(&err.message)
                    );
                }
            }
            EXIT_SCOPE_ERROR
        }
        Ok(res) => {
            let any_true = res.flags.values().any(|&v| v);
            let nothing_matched = !res.unmatched.is_empty() && !any_true;
            let error = if nothing_matched || (!res.unmatched.is_empty() && args.strict) {
                Some("unmatched")
            } else {
                None
            };
            let cap = res.unmatched.len().min(50);
            if args.json {
                let mut fobj = Map::new();
                for &f in FLAGS {
                    fobj.insert(
                        f.to_string(),
                        Value::Bool(*res.flags.get(f).unwrap_or(&false)),
                    );
                }
                let unm: Vec<Value> = res.unmatched[..cap]
                    .iter()
                    .map(|b| Value::String(String::from_utf8_lossy(b).into_owned()))
                    .collect();
                let payload = json!({
                    "flags": Value::Object(fobj),
                    "error": error,
                    "base": res.shown_base,
                    "unmatched": unm,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                for &f in FLAGS {
                    let v = *res.flags.get(f).unwrap_or(&false);
                    println!("SCOPE_{f}={}", if v { "true" } else { "false" });
                }
                if error.is_some() {
                    println!("SCOPE_ERROR=unmatched");
                }
                for path in &res.unmatched[..cap] {
                    println!("# unmatched: {}", shell_comment_bytes(path));
                }
            }
            if error.is_some() {
                EXIT_SCOPE_ERROR
            } else {
                EXIT_OK
            }
        }
    }
}
