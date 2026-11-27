//! Native Rust `floor_guard` engine — byte-for-byte compatible with `runtime/scripts/floor_guard.py`.

pub mod rules;
pub mod thresholds;
pub mod waivers;

use of_common::decisions;
use of_common::diffparse::{self, DiffRecord};
use of_common::gitexec::{self, Custody};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_CANNOT_RUN: i32 = 2;

const MOVE_SIMILARITY: f64 = 0.5;
const SUBSTANTIVE_LEN: usize = 6;
const DISCOVERY_PREFIXES: &[&str] = &["test", "Test"];

const DIFF_RENDERING: &[&str] = &[
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.srcPrefix=a/",
    "-c",
    "diff.dstPrefix=b/",
    "-c",
    "diff.relative=false",
    "-c",
    "color.diff=false",
];

const DIFF_OPTIONS: &[&str] = &[
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--text",
    "--no-color",
    "--unified=0",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: String,
    pub path: String,
    pub line: usize,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct FloorConfig {
    pub base: Option<String>,
    pub constraints: String,
    pub waivers: String,
    pub repo: PathBuf,
    pub quiet: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FloorReport {
    pub status: String,
    pub base: String,
    pub base_commit: String,
    pub findings: Vec<Finding>,
    pub waived: usize,
    pub exit_code: i32,
}

fn repo_root(start: &Path) -> Result<PathBuf, String> {
    let out = gitexec::run_git_repo(start, &["rev-parse", "--show-toplevel"], &[])?;
    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.code != 0 || top.is_empty() {
        return Err(format!("{} is not inside a git work tree", start.display()));
    }
    Ok(PathBuf::from(top))
}

fn merge_base(repo: &Path, base: &str) -> Result<String, String> {
    let out = gitexec::run_git_repo(repo, &["merge-base", base, "HEAD"], &[])?;
    let mb = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.code != 0 || mb.is_empty() {
        return Err(format!("no merge base between {base} and HEAD"));
    }
    Ok(mb)
}

pub fn read_at(repo: &Path, git_ref: &str, rel: &str) -> Result<Option<String>, String> {
    let list = gitexec::run_git_repo(
        repo,
        &[
            "ls-tree",
            "-z",
            "--name-only",
            "--full-tree",
            git_ref,
            "--",
            rel,
        ],
        &[],
    )?;
    if list.code != 0 {
        return Err(format!("cannot list {rel} at {git_ref}"));
    }
    let present = list
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .any(|name| name == rel.as_bytes());
    if !present {
        return Ok(None);
    }
    let spec = format!("{git_ref}:{rel}");
    let blob = gitexec::run_git_repo(repo, &["cat-file", "blob", &spec], &[])?;
    if blob.code != 0 {
        return Err(format!("{git_ref}:{rel} exists but could not be read"));
    }
    Ok(Some(String::from_utf8_lossy(&blob.stdout).into_owned()))
}

fn waiver_rel(repo: &Path, waivers_arg: &str) -> Result<String, String> {
    let p = Path::new(waivers_arg);
    let rel_path = if p.is_absolute() {
        let repo_canon = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
        let p_canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        p_canon.strip_prefix(&repo_canon).map_err(|_| {
            format!(
                "--waivers {waivers_arg} is outside the repository; waivers are read at the base ref, so they must name a repository path"
            )
        })?.to_path_buf()
    } else {
        p.to_path_buf()
    };
    let s = rel_path.to_string_lossy().replace('\\', "/");
    Ok(s.trim_start_matches("./").to_string())
}

pub fn collect_diff(repo: &Path, mb: &str) -> Result<String, String> {
    gitexec::refuse_blocking_files(repo)
        .map_err(|err| format!("git would block reading this repository: {err}"))?;
    let blanks = gitexec::driver_blanks(repo)?;
    let custody = Custody::open(repo)
        .map_err(|err| format!("cannot diff the working tree in git custody: {err}"))?;

    let mut diff_args: Vec<OsString> = DIFF_RENDERING.iter().map(OsString::from).collect();
    diff_args.push(OsString::from("diff"));
    diff_args.extend(DIFF_OPTIONS.iter().map(OsString::from));
    diff_args.push(OsString::from(gitexec::NO_SUBMODULE_CHILD));
    diff_args.push(OsString::from(mb));
    diff_args.push(OsString::from("--"));

    let tracked = custody.run(&diff_args, &blanks)?;
    if tracked.code != 0 {
        return Err("tracked/staged diff acquisition failed".to_string());
    }

    let ls_args: Vec<OsString> = ["ls-files", "-z", "--others", "--exclude-standard"]
        .iter()
        .map(OsString::from)
        .collect();
    let others = custody.run(&ls_args, &[])?;
    if others.code != 0 {
        return Err("untracked file enumeration failed".to_string());
    }

    let mut chunks = vec![String::from_utf8_lossy(&tracked.stdout).into_owned()];
    let dn = if cfg!(windows) { "NUL" } else { "/dev/null" };

    for raw_name in others.stdout.split(|&b| b == 0) {
        if raw_name.is_empty() {
            continue;
        }
        #[cfg(unix)]
        let name_os = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(raw_name.to_vec())
        };
        #[cfg(not(unix))]
        let name_os = OsString::from(String::from_utf8_lossy(raw_name).into_owned());

        let mut u_args: Vec<OsString> = DIFF_RENDERING.iter().map(OsString::from).collect();
        u_args.push(OsString::from("diff"));
        u_args.push(OsString::from("--no-index"));
        u_args.extend(DIFF_OPTIONS.iter().map(OsString::from));
        u_args.push(OsString::from("--"));
        u_args.push(OsString::from(dn));
        u_args.push(name_os);

        let r = custody
            .run(&u_args, &blanks)
            .map_err(|_| "untracked diff acquisition failed to run".to_string())?;
        if (r.code != 0 && r.code != 1) || (r.code == 1 && r.stdout.is_empty()) {
            return Err(format!(
                "untracked diff acquisition failed (exit {})",
                r.code
            ));
        }
        chunks.push(String::from_utf8_lossy(&r.stdout).into_owned());
    }
    Ok(chunks.join("\n"))
}

pub fn unquote_c(text: &str) -> Result<String, String> {
    if text.len() < 2 || !text.starts_with('"') || !text.ends_with('"') {
        return Ok(text.to_string());
    }
    let body = &text[1..text.len() - 1];
    let bytes = body.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            return Err(format!(
                "malformed C-quoted path in a diff header: {text:?}"
            ));
        }
        let esc = match bytes[i + 1] {
            b'a' => Some(7),
            b'b' => Some(8),
            b't' => Some(9),
            b'n' => Some(10),
            b'v' => Some(11),
            b'f' => Some(12),
            b'r' => Some(13),
            b'"' => Some(34),
            b'\\' => Some(92),
            _ => None,
        };
        if let Some(b) = esc {
            out.push(b);
            i += 2;
        } else if i + 3 < bytes.len()
            && (b'0'..=b'3').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let oct =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(oct);
            i += 4;
        } else {
            return Err(format!(
                "malformed C-quoted path in a diff header: {text:?}"
            ));
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub fn strip_prefix(raw: &str) -> Result<String, String> {
    let path = unquote_c(raw.trim())?;
    if let Some(rest) = path.strip_prefix("a/").or_else(|| path.strip_prefix("b/")) {
        return Ok(rest.to_string());
    }
    if path == "/dev/null" || path == "NUL" {
        return Ok(String::new());
    }
    Ok(path)
}

pub type DiffLine = (String, usize, String);

pub fn parse_diff(diff_text: &str) -> Result<(Vec<DiffLine>, Vec<DiffLine>), String> {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut new_path = String::new();
    let mut old_path = String::new();
    let mut new_no = 0usize;
    let mut old_no = 0usize;

    let recs = diffparse::records(diff_text)
        .map_err(|err| format!("diff is not a well-formed unified diff: {err}"))?;
    for rec in recs {
        match rec {
            DiffRecord::Header(line) => {
                if let Some(rest) = line.strip_prefix("--- ") {
                    old_path = strip_prefix(rest)
                        .map_err(|err| format!("diff is not a well-formed unified diff: {err}"))?;
                } else if let Some(rest) = line.strip_prefix("+++ ") {
                    new_path = strip_prefix(rest)
                        .map_err(|err| format!("diff is not a well-formed unified diff: {err}"))?;
                }
            }
            DiffRecord::Hunk {
                old_start,
                new_start,
                ..
            } => {
                old_no = old_start;
                new_no = new_start;
            }
            DiffRecord::Added(line) => {
                let p = if !new_path.is_empty() {
                    new_path.clone()
                } else {
                    old_path.clone()
                };
                added.push((p, new_no, line[1..].to_string()));
                new_no += 1;
            }
            DiffRecord::Removed(line) => {
                let p = if !old_path.is_empty() {
                    old_path.clone()
                } else {
                    new_path.clone()
                };
                removed.push((p, old_no, line[1..].to_string()));
                old_no += 1;
            }
            DiffRecord::Context(_) => {
                new_no += 1;
                old_no += 1;
            }
            DiffRecord::Marker(_) => {}
        }
    }
    Ok((added, removed))
}

fn flag_finding(findings: &mut Vec<Finding>, rule: &str, path: &str, line: usize, detail: &str) {
    findings.push(Finding {
        rule: rule.to_string(),
        path: if path.is_empty() {
            "(unknown)".to_string()
        } else {
            path.to_string()
        },
        line,
        detail: detail.to_string(),
    });
}

fn file_has_exceptions_heading(repo: &Path, path: &str) -> bool {
    let Ok(text) = fs::read_to_string(repo.join(path)) else {
        return false;
    };
    text.lines()
        .any(|ln| rules::exceptions_heading_re().is_match(ln))
}

fn file_rows(repo: &Path, path: &str) -> Vec<String> {
    let Ok(bytes) = fs::read(repo.join(path)) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    text.lines()
        .filter(|ln| ln.trim().starts_with('|'))
        .map(String::from)
        .collect()
}

fn flag_structural_guard_surface(
    added: &[DiffLine],
    removed: &[DiffLine],
    repo: &Path,
    base: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let mut first_line: BTreeMap<String, usize> = BTreeMap::new();
    for (path, line, _) in added.iter().chain(removed.iter()) {
        let base_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if matches!(base_name, "pyproject.toml" | "setup.cfg" | "tox.ini") {
            first_line.entry(path.clone()).or_insert(*line);
        }
    }
    if first_line.is_empty() {
        return;
    }
    let flagged_paths: HashSet<String> = findings
        .iter()
        .filter(|f| f.rule == "guard-surface")
        .map(|f| f.path.clone())
        .collect();

    for (path, line) in first_line {
        if flagged_paths.contains(&path) {
            continue;
        }
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let base_text = if let Some(b) = base {
            read_at(repo, b, &path).ok().flatten()
        } else if repo.join(".git").exists() {
            read_at(repo, "HEAD", &path).ok().flatten()
        } else {
            None
        };
        let head_path = repo.join(&path);
        let head_text = if head_path.exists() {
            match fs::read_to_string(&head_path) {
                Ok(s) => Some(s),
                Err(_) => {
                    flag_finding(findings, "guard-surface", &path, line, &path);
                    continue;
                }
            }
        } else {
            None
        };

        let changed = if name == "pyproject.toml" {
            match (
                rules::pyproject_guarded_sections(base_text.as_deref()),
                rules::pyproject_guarded_sections(head_text.as_deref()),
            ) {
                (Ok(before), Ok(after)) => before != after,
                _ => true,
            }
        } else {
            match (
                rules::ini_guarded_sections(base_text.as_deref()),
                rules::ini_guarded_sections(head_text.as_deref()),
            ) {
                (Ok(before), Ok(after)) => before != after,
                _ => true,
            }
        };
        if changed {
            flag_finding(findings, "guard-surface", &path, line, &path);
        }
    }
}

fn substantive_counts(lines: &[&str]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for line in lines {
        let t = line.trim();
        if t.len() >= SUBSTANTIVE_LEN && t.chars().any(|c| c.is_alphanumeric()) {
            *counts.entry(t.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

fn intersect_sum(a: &HashMap<String, usize>, b: &HashMap<String, usize>) -> usize {
    let mut total = 0usize;
    for (k, &va) in a {
        if let Some(&vb) = b.get(k) {
            total += va.min(vb);
        }
    }
    total
}

fn charge_moved_assertions(
    in_deleted_files: &BTreeMap<String, Vec<(usize, String)>>,
    added: &[DiffLine],
    removed: &[DiffLine],
    findings: &mut Vec<Finding>,
) {
    if in_deleted_files.is_empty() {
        return;
    }
    let mut added_by_path: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (p, _, t) in added {
        added_by_path
            .entry(p.as_str())
            .or_default()
            .push(t.as_str());
    }
    let mut removed_by_path: HashMap<&str, Vec<&str>> = HashMap::new();
    for (p, _, t) in removed {
        removed_by_path
            .entry(p.as_str())
            .or_default()
            .push(t.as_str());
    }
    let mut kept: HashMap<String, usize> = HashMap::new();
    for (p, _, t) in added {
        if rules::test_path_re().is_match(p) {
            *kept.entry(t.trim().to_string()).or_insert(0) += 1;
        }
    }

    for (path, dropped) in in_deleted_files {
        let old_lines = removed_by_path
            .get(path.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let old = substantive_counts(old_lines);
        let total: usize = old.values().sum();
        if total == 0 {
            continue;
        }
        let mut everywhere: HashMap<String, usize> = HashMap::new();
        let mut best: Option<&str> = None;
        let mut best_shared = 0usize;
        for (&other, lines) in &added_by_path {
            if other == path.as_str() {
                continue;
            }
            let new = substantive_counts(lines);
            for (k, &v) in &new {
                *everywhere.entry(k.clone()).or_insert(0) += v;
            }
            let shared = intersect_sum(&old, &new);
            if shared > best_shared {
                best = Some(other);
                best_shared = shared;
            }
        }
        let Some(dest) = best else {
            continue;
        };
        if (intersect_sum(&old, &everywhere) as f64) < MOVE_SIMILARITY * (total as f64) {
            continue;
        }
        for (line, text) in dropped {
            let trimmed = text.trim();
            if let Some(cnt) = kept.get_mut(trimmed) {
                if *cnt > 0 {
                    *cnt -= 1;
                    continue;
                }
            }
            flag_finding(
                findings,
                "assertion-removed",
                dest,
                *line,
                &format!("dropped moving from {path}:{line}"),
            );
        }
    }
}

fn flag_undiscoverable_renames(
    added: &[DiffLine],
    removed: &[DiffLine],
    findings: &mut Vec<Finding>,
) {
    let mut removed_defs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, _, text) in removed {
        if rules::test_path_re().is_match(path) {
            if let Some(caps) = rules::test_def_re().captures(text) {
                let name = &caps[1];
                if DISCOVERY_PREFIXES.iter().any(|p| name.starts_with(p)) {
                    removed_defs
                        .entry(path.clone())
                        .or_default()
                        .push(name.to_string());
                }
            }
        }
    }
    if removed_defs.is_empty() {
        return;
    }
    let mut added_defs: HashMap<&str, Vec<(String, usize)>> = HashMap::new();
    for (path, line, text) in added {
        if removed_defs.contains_key(path) {
            if let Some(caps) = rules::test_def_re().captures(text) {
                added_defs
                    .entry(path.as_str())
                    .or_default()
                    .push((caps[1].to_string(), *line));
            }
        }
    }
    for (path, names) in removed_defs {
        let new = added_defs
            .get(path.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let still_defined: HashSet<&str> = new.iter().map(|(n, _)| n.as_str()).collect();
        for name in names {
            if still_defined.contains(name.as_str()) {
                continue;
            }
            let prefix = &name[..4.min(name.len())];
            let name_low = name.to_ascii_lowercase();
            for (other, line) in new {
                if other != &name
                    && other.to_ascii_lowercase().ends_with(&name_low)
                    && !other.starts_with(prefix)
                {
                    flag_finding(
                        findings,
                        "test-made-easier",
                        &path,
                        *line,
                        "renamed-out-of-discovery",
                    );
                    break;
                }
            }
        }
    }
}

fn flag_lowered_rows(
    added: &[DiffLine],
    removed: &[DiffLine],
    constraints_name: &str,
    findings: &mut Vec<Finding>,
    repo: &Path,
) {
    let mut partners: HashMap<(String, String), Vec<String>> = HashMap::new();
    for (path, _, text) in added {
        if thresholds::is_constraints(path, constraints_name) {
            partners
                .entry((path.clone(), thresholds::shape_key(text)))
                .or_default()
                .push(text.clone());
        }
    }
    for (path, line, text) in removed {
        if !thresholds::is_constraints(path, constraints_name) {
            continue;
        }
        let key = thresholds::shape_key(text);
        let before = thresholds::numbers(text);
        if key.is_empty() || before.is_empty() {
            continue;
        }
        let partner = partners.get_mut(&(path.clone(), key)).and_then(|pool| {
            if pool.is_empty() {
                None
            } else {
                Some(pool.remove(0))
            }
        });
        match partner {
            None => {
                flag_finding(
                    findings,
                    "threshold-lowered",
                    path,
                    *line,
                    "row removed or re-keyed",
                );
            }
            Some(after) => {
                if let Some(detail) = thresholds::lowering(text, &after) {
                    flag_finding(findings, "threshold-lowered", path, *line, &detail);
                }
            }
        }
    }
    for (path, line, text) in added {
        let key = thresholds::shape_key(text);
        if !(thresholds::is_constraints(path, constraints_name)
            && key.starts_with("row:")
            && !thresholds::numbers(text).is_empty())
        {
            continue;
        }
        let count = file_rows(repo, path)
            .into_iter()
            .filter(|t| thresholds::shape_key(t) == key)
            .count();
        if count > 1 {
            flag_finding(
                findings,
                "threshold-lowered",
                path,
                *line,
                &format!("duplicate row for {}", &key[4..]),
            );
        }
    }
}

pub fn scan(
    added: &[DiffLine],
    removed: &[DiffLine],
    constraints_name: &str,
    repo: &Path,
    base: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_exceptions: HashMap<String, bool> = HashMap::new();

    for (path, line, text) in added {
        if thresholds::is_constraints(path, constraints_name)
            && rules::exceptions_heading_re().is_match(text)
        {
            in_exceptions.insert(path.clone(), true);
        }
        let mut surface = rules::guard_surface_hit(path, text);
        if surface.is_none() && path == ".coveragerc" && rules::is_coveragerc_section(text) {
            surface = Some(".coveragerc".to_string());
        }
        if let Some(surf) = surface {
            flag_finding(&mut findings, "guard-surface", path, *line, &surf);
        }
        if rules::is_media(path) {
            continue;
        }
        for (name, pat) in rules::suppressions() {
            if pat.is_match(text) {
                flag_finding(&mut findings, "silenced-checker", path, *line, name);
                break;
            }
        }
        for (name, pat) in rules::skips() {
            if pat.is_match(text) {
                flag_finding(&mut findings, "test-made-easier", path, *line, name);
                break;
            }
        }
        for (name, pat) in rules::stubs() {
            if pat.is_match(text) {
                flag_finding(&mut findings, "unfinished-work", path, *line, name);
                break;
            }
        }
        if thresholds::is_constraints(path, constraints_name) {
            if rules::exception_row_re().is_match(text) {
                flag_finding(&mut findings, "new-exception", path, *line, "exception-row");
            } else {
                let trimmed = text.trim();
                if (trimmed.starts_with('-') || trimmed.starts_with('*'))
                    && (*in_exceptions.get(path).unwrap_or(&false)
                        || file_has_exceptions_heading(repo, path))
                {
                    flag_finding(
                        &mut findings,
                        "new-exception",
                        path,
                        *line,
                        "exceptions-bullet",
                    );
                }
            }
        }
    }

    let mut gone_cache: HashMap<String, bool> = HashMap::new();
    let mut in_deleted_files: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();

    for (path, line, text) in removed {
        let mut surface = rules::guard_surface_hit(path, text);
        if surface.is_none() && path == ".coveragerc" && rules::is_coveragerc_section(text) {
            surface = Some(".coveragerc".to_string());
        }
        if let Some(surf) = surface {
            flag_finding(&mut findings, "guard-surface", path, *line, &surf);
        }
        if rules::is_media(path) || !rules::test_path_re().is_match(path) {
            continue;
        }
        if !rules::assertions_re().is_match(text) {
            continue;
        }
        let is_gone = *gone_cache.entry(path.clone()).or_insert_with(|| {
            let spec = format!("HEAD:{path}");
            let in_head = gitexec::run_git_repo(repo, &["cat-file", "-e", &spec], &[])
                .map(|o| o.code == 0)
                .unwrap_or(false);
            !in_head && !repo.join(path).exists()
        });
        if is_gone {
            in_deleted_files
                .entry(path.clone())
                .or_default()
                .push((*line, text.clone()));
            continue;
        }
        flag_finding(&mut findings, "assertion-removed", path, *line, "assertion");
    }

    flag_structural_guard_surface(added, removed, repo, base, &mut findings);

    let added_code: Vec<DiffLine> = added
        .iter()
        .filter(|(p, _, _)| !rules::is_media(p))
        .cloned()
        .collect();
    let removed_code: Vec<DiffLine> = removed
        .iter()
        .filter(|(p, _, _)| !rules::is_media(p))
        .cloned()
        .collect();

    charge_moved_assertions(&in_deleted_files, &added_code, &removed_code, &mut findings);
    flag_undiscoverable_renames(&added_code, &removed_code, &mut findings);
    flag_lowered_rows(
        &added_code,
        &removed_code,
        constraints_name,
        &mut findings,
        repo,
    );
    findings
}

pub fn run(cfg: &FloorConfig) -> i32 {
    let run_res = (|| -> Result<FloorReport, String> {
        let repo = repo_root(&cfg.repo)?;
        let resolved = gitexec::base_commit(&repo, cfg.base.as_deref())?;
        if let Some(local_kind) = &resolved.local {
            if let Some(lane) = gitexec::sound_lane() {
                return Err(format!(
                    "{lane} claims a sound lane, but base {:?} is {local_kind} ({}), not a remote-tracking ref or a full commit id: there the waivers and the human-grant pin are read only at one of those — --base origin/<branch> or a full commit id (W3-07)",
                    resolved.shown,
                    &resolved.commit[..12.min(resolved.commit.len())]
                ));
            }
            if !cfg.json {
                eprintln!(
                    "floor-guard: NOTE — base {:?} is {local_kind} ({}), not a remote-tracking ref or a full commit id: the change under check can move a local name and nothing binds an abbreviation, so the waivers and the human-grant pin read there are advisory; --base origin/<branch> (or a full commit id) reads them where it cannot write",
                    resolved.shown,
                    &resolved.commit[..12.min(resolved.commit.len())]
                );
            }
        }
        let mb = merge_base(&repo, &resolved.commit)?;
        let diff_text = collect_diff(&repo, &mb)?;
        let (added, removed) = parse_diff(&diff_text)?;
        let findings = scan(&added, &removed, &cfg.constraints, &repo, Some(&mb));

        let wrel = waiver_rel(&repo, &cfg.waivers)?;
        let waiver_text = read_at(&repo, &resolved.commit, &wrel)?;
        let waiver_lines: Vec<String> = waiver_text
            .map(|t| {
                t.lines()
                    .filter(|ln| !ln.trim().is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        if !cfg.json {
            for (raw, why) in waivers::malformed_waivers(&waiver_lines) {
                let snippet: String = raw.trim().chars().take(200).collect();
                eprintln!(
                    "floor-guard: NOT a usable waiver — {why}:\n  {snippet}\n  write the id as `floor-waiver:<rule>:<path>` (or `:<dir>/**`), class `one-way`, answer `allow`"
                );
            }
        }

        let pub_text = read_at(&repo, &resolved.commit, decisions::GRANT_PUBKEY_REL)?;
        let grant_pub = match pub_text {
            None => None,
            Some(txt) => {
                let where_lbl = format!("{}:{}", resolved.commit, decisions::GRANT_PUBKEY_REL);
                Some(decisions::parse_grant_pubkey(&txt, &where_lbl)?)
            }
        };

        let live: Vec<Finding> = findings
            .iter()
            .filter(|f| !waivers::is_waived(f, &waiver_lines, grant_pub.as_ref()))
            .cloned()
            .collect();
        let waived_count = findings.len() - live.len();

        if live.is_empty() {
            if !cfg.json && !cfg.quiet {
                let note = if waived_count > 0 {
                    format!(" ({waived_count} waived)")
                } else {
                    String::new()
                };
                println!("floor-guard: clean{note}");
            }
            return Ok(FloorReport {
                status: "clean".to_string(),
                base: resolved.shown,
                base_commit: resolved.commit,
                findings: Vec::new(),
                waived: waived_count,
                exit_code: EXIT_CLEAN,
            });
        }

        if !cfg.json {
            eprintln!("floor-guard: {} floor violation(s):", live.len());
            for f in &live {
                eprintln!("  [{}] {}:{} ({})", f.rule, f.path, f.line, f.detail);
                for (raw, why) in waivers::refused_waivers(f, &waiver_lines, grant_pub.as_ref()) {
                    let snippet: String = raw.trim().chars().take(200).collect();
                    eprintln!(
                        "      waiver at {} not honoured — {why}:\n        {snippet}",
                        resolved.shown
                    );
                }
            }
            eprintln!(
                "\nEach lowers the bar. Fix the code, or land a waiver on {} FIRST: a DECISIONS record whose id is `floor-waiver:<rule>:<path>` (or `:<dir>/**`), class `one-way`, answer `allow`, appended with `decisions.py append --source human:<name>` (plus `--grant-sig` when .orca/human-grant-pubkey is pinned). Waivers are read at the base ref; one this change writes for itself is not.",
                resolved.shown
            );
        }

        Ok(FloorReport {
            status: "findings".to_string(),
            base: resolved.shown,
            base_commit: resolved.commit,
            findings: live,
            waived: waived_count,
            exit_code: EXIT_FINDINGS,
        })
    })();

    match run_res {
        Ok(report) => {
            if cfg.json {
                if let Ok(s) = serde_json::to_string_pretty(&report) {
                    println!("{s}");
                }
            }
            report.exit_code
        }
        Err(err) => {
            if cfg.json {
                let payload = serde_json::json!({
                    "status": "error",
                    "error": err,
                    "exit_code": EXIT_CANNOT_RUN,
                });
                println!("{payload}");
            } else {
                eprintln!("floor-guard: could not run: {err}");
            }
            EXIT_CANNOT_RUN
        }
    }
}
