//! Unified-diff parsing, path inventory, hunk coordinates, and change-binding engine —
//! native Rust port of `runtime/scripts/_verify_diff.py`.

use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Line coordinate in doubled-units so integers are `2*n` and half-integer insertion seams
/// `n - 0.5` are `2*n - 1` (exact total ordering & equality without floating-point inaccuracy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Coord(pub i64);

impl Coord {
    pub fn whole(n: i64) -> Self {
        Coord(n * 2)
    }

    pub fn seam_before(n: i64) -> Self {
        Coord(n * 2 - 1)
    }

    pub fn is_whole(self) -> bool {
        self.0 % 2 == 0
    }

    pub fn format_py(self) -> String {
        if self.is_whole() {
            format!("{}", self.0 / 2)
        } else {
            let half = self.0 as f64 / 2.0;
            format!("{half}")
        }
    }
}

fn hunk_hdr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").expect("regex"))
}

pub fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// POSIX shlex.split (comments=false by default, or comments=true).
pub fn shlex_split(input: &str, comments: bool) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut has_tok = false;
    let mut chars = input.chars().peekable();

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        Single,
        Double,
    }
    let mut state = State::Normal;

    while let Some(ch) = chars.next() {
        match state {
            State::Normal => {
                if ch == '#' && comments && !has_tok {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                    continue;
                }
                if ch.is_ascii_whitespace() {
                    if has_tok {
                        tokens.push(std::mem::take(&mut cur));
                        has_tok = false;
                    }
                } else if ch == '\'' {
                    state = State::Single;
                    has_tok = true;
                } else if ch == '"' {
                    state = State::Double;
                    has_tok = true;
                } else if ch == '\\' {
                    has_tok = true;
                    if let Some(next) = chars.next() {
                        if next != '\n' {
                            cur.push(next);
                        }
                    } else {
                        return Err("No escaped character".to_string());
                    }
                } else {
                    has_tok = true;
                    cur.push(ch);
                }
            }
            State::Single => {
                if ch == '\'' {
                    state = State::Normal;
                } else {
                    cur.push(ch);
                }
            }
            State::Double => {
                if ch == '"' {
                    state = State::Normal;
                } else if ch == '\\' {
                    if let Some(&next) = chars.peek() {
                        if matches!(next, '"' | '\\' | '$' | '`' | '\n') {
                            chars.next();
                            if next != '\n' {
                                cur.push(next);
                            }
                        } else {
                            cur.push('\\');
                        }
                    } else {
                        return Err("No closing quotation".to_string());
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if state != State::Normal {
        return Err("No closing quotation".to_string());
    }
    if has_tok {
        tokens.push(cur);
    }
    Ok(tokens)
}

pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
            )
    });
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

pub fn shlex_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecKind {
    Header,
    Hunk,
    Del,
    Add,
    Ctx,
}

pub fn diff_records(diff: &str) -> Result<Vec<(RecKind, &str)>, String> {
    let mut old_left: i64 = 0;
    let mut new_left: i64 = 0;
    let mut lines: Vec<&str> = diff.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if line == r"\ No newline at end of file" {
            continue;
        }
        let kind = if old_left != 0 || new_left != 0 {
            let first = line.as_bytes().first().copied();
            match first {
                Some(b'-') => {
                    old_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    RecKind::Del
                }
                Some(b'+') => {
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    RecKind::Add
                }
                Some(b' ') => {
                    old_left -= 1;
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    RecKind::Ctx
                }
                _ => return Err("incomplete diff hunk".to_string()),
            }
        } else if line.starts_with("@@") {
            let Some(caps) = hunk_hdr_re().captures(line) else {
                return Err("malformed hunk header".to_string());
            };
            old_left = caps
                .get(2)
                .map(|m| m.as_str().parse::<i64>().unwrap_or(1))
                .unwrap_or(1);
            new_left = caps
                .get(4)
                .map(|m| m.as_str().parse::<i64>().unwrap_or(1))
                .unwrap_or(1);
            RecKind::Hunk
        } else {
            RecKind::Header
        };
        out.push((kind, line));
    }
    if old_left != 0 || new_left != 0 {
        return Err("incomplete diff hunk".to_string());
    }
    Ok(out)
}

/// Inventory target paths; returns `(paths_found_before_any_error, optional_error)` so callers can
/// preserve partial decoy diagnostics even when a patch is truncated (matching verify.py line 3817).
pub fn iter_diff_target_paths<F>(diff: &str, resolve: F) -> (BTreeSet<String>, Option<String>)
where
    F: Fn(&str) -> (Option<PathBuf>, Option<String>),
{
    let mut found = BTreeSet::new();
    let mut old_left: i64 = 0;
    let mut new_left: i64 = 0;
    let mut lines: Vec<&str> = diff.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    for line in lines {
        if line == r"\ No newline at end of file" {
            continue;
        }
        let kind = if old_left != 0 || new_left != 0 {
            match line.as_bytes().first().copied() {
                Some(b'-') => {
                    old_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return (
                            found,
                            Some("diff hunk exceeds declared line counts".to_string()),
                        );
                    }
                    RecKind::Del
                }
                Some(b'+') => {
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return (
                            found,
                            Some("diff hunk exceeds declared line counts".to_string()),
                        );
                    }
                    RecKind::Add
                }
                Some(b' ') => {
                    old_left -= 1;
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return (
                            found,
                            Some("diff hunk exceeds declared line counts".to_string()),
                        );
                    }
                    RecKind::Ctx
                }
                _ => return (found, Some("incomplete diff hunk".to_string())),
            }
        } else if line.starts_with("@@") {
            let Some(caps) = hunk_hdr_re().captures(line) else {
                return (found, Some("malformed hunk header".to_string()));
            };
            old_left = caps
                .get(2)
                .map(|m| m.as_str().parse::<i64>().unwrap_or(1))
                .unwrap_or(1);
            new_left = caps
                .get(4)
                .map(|m| m.as_str().parse::<i64>().unwrap_or(1))
                .unwrap_or(1);
            RecKind::Hunk
        } else {
            RecKind::Header
        };

        if kind != RecKind::Header {
            continue;
        }
        let mut prefixed = true;
        let values: Vec<String> = if let Some(rest) = line.strip_prefix("diff --git ") {
            match shlex_split(rest, false) {
                Ok(v) if v.len() == 2 => v,
                _ => return (found, Some("ambiguous diff path header".to_string())),
            }
        } else if line.starts_with("--- ") || line.starts_with("+++ ") {
            let v = line[4..].split('\t').next().unwrap_or("");
            vec![v.to_string()]
        } else if line.starts_with("rename from ")
            || line.starts_with("rename to ")
            || line.starts_with("copy from ")
            || line.starts_with("copy to ")
        {
            prefixed = false;
            let mut parts = line.splitn(3, ' ');
            let _ = parts.next();
            let _ = parts.next();
            vec![parts.next().unwrap_or("").to_string()]
        } else {
            continue;
        };

        for raw_val in values {
            if raw_val == "/dev/null" {
                continue;
            }
            if raw_val.starts_with('"') || raw_val.contains('\\') {
                return (
                    found,
                    Some(
                        "quoted diff paths are not supported; use an unambiguous patch".to_string(),
                    ),
                );
            }
            let val = if prefixed && (raw_val.starts_with("a/") || raw_val.starts_with("b/")) {
                raw_val[2..].to_string()
            } else {
                raw_val
            };
            let (_, err) = resolve(&val);
            if err.is_some() || val.is_empty() || val.starts_with('-') {
                return (found, Some(format!("invalid diff path: {val:?}")));
            }
            found.insert(val);
        }
    }
    if old_left != 0 || new_left != 0 {
        return (found, Some("incomplete diff hunk".to_string()));
    }
    (found, None)
}

pub fn diff_target_paths<F>(diff: &str, resolve: F) -> Result<Vec<String>, String>
where
    F: Fn(&str) -> (Option<PathBuf>, Option<String>),
{
    let (set, err) = iter_diff_target_paths(diff, resolve);
    if let Some(e) = err {
        return Err(e);
    }
    Ok(set.into_iter().collect())
}

pub fn hunk_lines(text: &str, side: char) -> Result<BTreeMap<String, BTreeSet<Coord>>, String> {
    let mut out: BTreeMap<String, BTreeSet<Coord>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut old_path: Option<String> = None;
    let mut old: i64 = 0;
    let mut new: i64 = 0;
    let mut removed: Vec<(i64, i64)> = Vec::new();
    let mut added: Vec<(i64, i64)> = Vec::new();

    let flush = |out: &mut BTreeMap<String, BTreeSet<Coord>>,
                 current: &Option<String>,
                 removed: &mut Vec<(i64, i64)>,
                 added: &mut Vec<(i64, i64)>| {
        if let Some(cur) = current {
            if !removed.is_empty() || !added.is_empty() {
                let (own, other) = if side == '-' {
                    (&*removed, &*added)
                } else {
                    (&*added, &*removed)
                };
                let entry = out.entry(cur.clone()).or_default();
                if !own.is_empty() {
                    for &(line_no, _) in own {
                        entry.insert(Coord::whole(line_no));
                    }
                } else if let Some(&(_, opp_line)) = other.first() {
                    entry.insert(Coord::seam_before(opp_line));
                }
            }
        }
        removed.clear();
        added.clear();
    };

    for (kind, line) in diff_records(text)? {
        match kind {
            RecKind::Header if line.starts_with("diff --git ") => {
                flush(&mut out, &current, &mut removed, &mut added);
                old = 0;
                new = 0;
                current = None;
            }
            RecKind::Header if line.starts_with("--- ") => {
                old_path = Some(line[4..].split('\t').next().unwrap_or("").to_string());
            }
            RecKind::Header if line.starts_with("+++ ") => {
                flush(&mut out, &current, &mut removed, &mut added);
                let new_p = line[4..].split('\t').next().unwrap_or("").to_string();
                let target = if side == '-' {
                    old_path.clone().unwrap_or_default()
                } else {
                    new_p
                };
                let stripped = if target.starts_with("a/") || target.starts_with("b/") {
                    target[2..].to_string()
                } else {
                    target
                };
                if !stripped.is_empty() && stripped != "/dev/null" {
                    out.entry(stripped.clone()).or_default();
                    current = Some(stripped);
                } else {
                    current = None;
                }
            }
            RecKind::Hunk => {
                flush(&mut out, &current, &mut removed, &mut added);
                let Some(caps) = hunk_hdr_re().captures(line) else {
                    return Err("malformed hunk header".to_string());
                };
                let a: i64 = caps[1].parse().unwrap_or(0);
                let ac = caps.get(2).map(|m| m.as_str());
                let b: i64 = caps[3].parse().unwrap_or(0);
                let bc = caps.get(4).map(|m| m.as_str());
                old = a + i64::from(ac == Some("0"));
                new = b + i64::from(bc == Some("0"));
            }
            RecKind::Del => {
                removed.push((old, new));
                old += 1;
            }
            RecKind::Add => {
                added.push((new, old));
                new += 1;
            }
            RecKind::Ctx => {
                flush(&mut out, &current, &mut removed, &mut added);
                old += 1;
                new += 1;
            }
            RecKind::Header => {}
        }
    }
    flush(&mut out, &current, &mut removed, &mut added);
    out.remove("/dev/null");
    Ok(out)
}

pub fn bind_hunks_to_change<F, G>(
    diff: &str,
    m: &Value,
    oracle_scope: Option<&Value>,
    resolve: F,
    git: G,
) -> Option<String>
where
    F: Fn(&str) -> (Option<PathBuf>, Option<String>) + Copy,
    G: Fn(&[&str]) -> (i32, String),
{
    let base = m.get("base_sha").and_then(|v| v.as_str()).unwrap_or("");
    let head = m.get("head_sha").and_then(|v| v.as_str()).unwrap_or("");
    if !is_hex40(base) || !is_hex40(head) {
        return Some(
            "the hand mutant cannot be bound to the change without pinned base_sha and head_sha"
                .to_string(),
        );
    }
    let touched = match hunk_lines(diff, '-') {
        Ok(t) => t,
        Err(e) => return Some(e),
    };
    let targets = match diff_target_paths(diff, resolve) {
        Ok(t) => t,
        Err(e) => return Some(e),
    };
    let target_set: BTreeSet<String> = targets.into_iter().collect();
    let touched_keys: BTreeSet<String> = touched.keys().cloned().collect();
    if target_set != touched_keys {
        return Some(
            "the hand mutant has a deleted, renamed or mode-only path without bound hunks"
                .to_string(),
        );
    }
    let range = format!("{base}..{head}");
    for (path, lines) in &touched {
        let (code, out) = git(&[
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "-U0",
            &range,
            "--",
            path,
        ]);
        if code != 0 {
            return Some(format!(
                "cannot diff {path} over base_sha..head_sha to bind the hand mutant to the change; fail-closed"
            ));
        }
        let changed: BTreeSet<Coord> = if let Some(scope) = oracle_scope {
            scope
                .get("paths")
                .and_then(|p| p.get(path))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_i64().map(Coord::whole))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            match hunk_lines(&out, '+') {
                Ok(mut map) => map.remove(path).unwrap_or_default(),
                Err(e) => return Some(e),
            }
        };
        if lines.is_empty() {
            return Some(format!(
                "the hand mutant's diff names {path} but carries no hunk for it, so nothing says which behaviour it mutates (#280)"
            ));
        }
        let mut allowed = changed.clone();
        for &c in &changed {
            if c.is_whole() {
                allowed.insert(Coord(c.0 - 1));
                allowed.insert(Coord(c.0 + 1));
            }
        }
        if !lines.is_subset(&allowed) {
            let show_lines: Vec<String> = lines.iter().take(6).map(|c| c.format_py()).collect();
            let show_changed = if changed.is_empty() {
                "'none'".to_string()
            } else {
                let s: Vec<String> = changed.iter().take(6).map(|c| c.format_py()).collect();
                format!("[{}]", s.join(", "))
            };
            return Some(format!(
                "the hand mutant touches {path} at line(s) [{}], and base_sha..head_sha changes line(s) {} there — \
                 they do not overlap completely. Mutating an untouched hunk of a changed file is the same \
                 decoy as mutating an untouched file: the RED comes from behaviour this unit did not introduce (#280)",
                show_lines.join(", "),
                show_changed
            ));
        }
    }
    None
}

pub fn nc_paths<F>(nc: &Value, resolve: F) -> (Option<Vec<String>>, Option<String>)
where
    F: Fn(&str) -> (Option<PathBuf>, Option<String>),
{
    let Some(raw) = nc.get("paths") else {
        return (None, None);
    };
    if raw.is_null() {
        return (None, None);
    }
    let Some(arr) = raw.as_array() else {
        return (
            None,
            Some(
                "negative_control.paths must be a non-empty list of repo-relative path strings"
                    .to_string(),
            ),
        );
    };
    if arr.is_empty() {
        return (
            None,
            Some(
                "negative_control.paths must be a non-empty list of repo-relative path strings"
                    .to_string(),
            ),
        );
    }
    let mut paths = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(s) = item.as_str() else {
            return (
                None,
                Some(
                    "negative_control.paths must be a non-empty list of repo-relative path strings"
                        .to_string(),
                ),
            );
        };
        if s.is_empty() {
            return (
                None,
                Some(
                    "negative_control.paths must be a non-empty list of repo-relative path strings"
                        .to_string(),
                ),
            );
        }
        if s.starts_with('-') {
            return (
                None,
                Some(format!(
                    "refusing option-like path in negative_control.paths: {s}"
                )),
            );
        }
        let (_, err) = resolve(s);
        if let Some(e) = err {
            return (None, Some(format!("negative_control.paths: {e}")));
        }
        paths.push(s.to_string());
    }
    (Some(paths), None)
}

pub fn extract_diff(text: &str) -> Option<String> {
    let lines: Vec<&str> = text
        .split('\n')
        .map(|ln| ln.strip_suffix('\r').unwrap_or(ln))
        .collect();
    let start = lines
        .iter()
        .position(|ln| ln.starts_with("diff --git ") || ln.starts_with("--- "))?;
    let mut end = start;
    for (offset, ln) in lines[start..].iter().enumerate() {
        let i = start + offset;
        let ok = ln.starts_with("diff --git ")
            || ln.starts_with("index ")
            || ln.starts_with("--- ")
            || ln.starts_with("+++ ")
            || ln.starts_with("@@")
            || ln.starts_with('+')
            || ln.starts_with('-')
            || ln.starts_with(' ')
            || ln.starts_with("new file mode")
            || ln.starts_with("deleted file mode")
            || ln.starts_with("similarity index")
            || ln.starts_with("rename from")
            || ln.starts_with("rename to")
            || ln.starts_with("old mode")
            || ln.starts_with("new mode")
            || *ln == r"\ No newline at end of file"
            || ln.is_empty();
        if ok {
            end = i;
        } else {
            break;
        }
    }
    let body = lines[start..=end].join("\n");
    let body = body.trim_end_matches('\n');
    if body.trim().is_empty() {
        None
    } else {
        Some(format!("{body}\n"))
    }
}
