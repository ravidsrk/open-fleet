//! Static pattern registries and guard-surface classification for `of-floor`,
//! mirroring `runtime/scripts/floor_guard.py`.
//!
//! Pattern literals are built with compile-time `concat!` so this source file never trips the
//! very suppression/skip/stub rules it enforces.

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

pub const GUARD_SURFACE_FILES: &[&str] = &[
    ".gitleaksignore",
    ".gitleaks.toml",
    ".orca/human-grant-pubkey",
    "evals/routing.json",
    "bench/vf-bench/VERSION",
    "bench/vf-bench/CANARY",
];

pub const GUARD_SURFACE_DIRS: &[&str] = &["bench/vf-bench/traps/"];

pub const BINARY_MEDIA: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".heic",
    ".mp4", ".mov", ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".woff", ".woff2", ".ttf", ".otf",
    ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".jar", ".pyc",
];

pub fn suppressions() -> &'static [(&'static str, Regex)] {
    static LIST: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            (
                "noqa",
                Regex::new(concat!("#", r"\s*no", "qa")).expect("regex"),
            ),
            (
                "type-ignore",
                Regex::new(concat!("#", r"\s*type:\s*ig", "nore")).expect("regex"),
            ),
            (
                "pragma-no-cover",
                Regex::new(concat!("prag", r"ma:\s*no\s*cov", "er")).expect("regex"),
            ),
            (
                concat!("esl", "int-dis", "able"),
                Regex::new(concat!("esl", "int-dis", "able")).expect("regex"),
            ),
            (
                "ts-ignore",
                Regex::new(concat!("@t", "s-(ig", "nore|no", "check|expect-error)"))
                    .expect("regex"),
            ),
            (
                concat!("bio", "me-ig", "nore"),
                Regex::new(concat!("bio", "me-ig", "nore")).expect("regex"),
            ),
            (
                "istanbul-ignore",
                Regex::new(concat!("istan", r"bul\s+ig", "nore")).expect("regex"),
            ),
            (
                concat!("nosem", "grep"),
                Regex::new(concat!("nosem", "grep")).expect("regex"),
            ),
            (
                "gitleaks-allow",
                Regex::new(concat!("gitle", "aks:al", "low")).expect("regex"),
            ),
            (
                "rust-allow",
                Regex::new(concat!(r"#\[al", r"low\(")).expect("regex"),
            ),
            (
                "golangci-nolint",
                Regex::new(concat!(r"//\s*no", "lint")).expect("regex"),
            ),
            (
                "stryker-disable",
                Regex::new(concat!("Stry", r"ker\s+dis", "able")).expect("regex"),
            ),
            (
                concat!("pret", "tier-ig", "nore"),
                Regex::new(concat!("pret", "tier-ig", "nore")).expect("regex"),
            ),
            (
                "phpstan-ignore",
                Regex::new(concat!("@php", "stan-ig", "nore")).expect("regex"),
            ),
        ]
    })
}

pub fn skips() -> &'static [(&'static str, Regex)] {
    static LIST: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            (
                "pytest-skip",
                Regex::new(concat!(
                    r"@?pyt",
                    r"est\.mark\.(sk",
                    "ip|sk",
                    "ipif|xf",
                    "ail)"
                ))
                .expect("regex"),
            ),
            (
                "unittest-skip",
                Regex::new(concat!(r"@?unit", r"test\.(sk", "ip|expectedFailure)")).expect("regex"),
            ),
            (
                "skiptest-call",
                Regex::new(concat!(r"\bsk", r"ipTest\s*\(")).expect("regex"),
            ),
            (
                "raise-skiptest",
                Regex::new(concat!(r"\braise\s+(?:\w+\.)*Sk", r"ipTest\b")).expect("regex"),
            ),
            (
                "pytest-skip-call",
                Regex::new(concat!(r"\bpyt", r"est\.(sk", "ip|xf", r"ail)\s*\(")).expect("regex"),
            ),
            (
                "decorator-skip",
                Regex::new(concat!(
                    r"^\s*@(sk",
                    "ip|Sk",
                    "ip|Ig",
                    "nore|Disabled)",
                    r"\b"
                ))
                .expect("regex"),
            ),
            (
                "dot-skip",
                Regex::new(concat!(r"\.(sk", "ip|on", "ly|to", r"do|failing)\s*\("))
                    .expect("regex"),
            ),
            (
                "xit",
                Regex::new(concat!(r"\bx(i", "t|desc", r"ribe|test|context)\s*\(")).expect("regex"),
            ),
            (
                "go-skip",
                Regex::new(concat!(r"\b[tb]\.Sk", r"ip(Now|f)?\s*\(")).expect("regex"),
            ),
            (
                "rust-ignore",
                Regex::new(concat!(r"#\[ig", "nore")).expect("regex"),
            ),
            (
                "junit-ignore",
                Regex::new(concat!(r"@(Ig", r"nore|Disabled)\b")).expect("regex"),
            ),
        ]
    })
}

pub fn stubs() -> &'static [(&'static str, Regex)] {
    static LIST: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            (
                "todo-marker",
                Regex::new(concat!(r"\b(TO", "DO|FIX", "ME|XX", "X|HA", r"CK)\b")).expect("regex"),
            ),
            (
                "not-implemented",
                Regex::new(concat!(
                    "(NotImple",
                    "mentedError|not",
                    r"\s+imple",
                    "mented|unimple",
                    "mented!)"
                ))
                .expect("regex"),
            ),
            (
                "empty-catch",
                Regex::new(concat!("cat", r"ch\s*(\([^)]*\))?\s*\{\s*\}")).expect("regex"),
            ),
            (
                "swallowed-except",
                Regex::new(concat!("exc", r"ept[^:]*:\s*pa", r"ss\b")).expect("regex"),
            ),
            (
                "stub-return",
                Regex::new(concat!(
                    r#"(?i)return\s+(None|null|nil|\{\}|\[\]|""|'')\s*(#|//)\s*(TO"#,
                    "DO|st",
                    "ub)"
                ))
                .expect("regex"),
            ),
            (
                "pass-stub",
                Regex::new(concat!(r"\bpa", r"ss\s*(#|//)\s*st", "ub")).expect("regex"),
            ),
        ]
    })
}

pub fn assertions_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(\bass",
            r"ert\b|\bexp",
            r"ect\s*\(|\bsho",
            r"uld\b|self\.ass",
            r"ert|\bt\.Err",
            "or)"
        ))
        .expect("regex")
    })
}

pub fn test_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|/)(tests?|spec|__tests__)/|\.(test|spec)\.|_test\.|(^|/)test_[^/]*$")
            .expect("regex")
    })
}

pub fn exception_row_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*\|\s*[WE]\d+\s*\|").expect("regex"))
}

pub fn exceptions_heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*#{1,6}\s+.*\bexceptions?\b").expect("regex"))
}

pub fn test_def_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*(?:async\s+def|def|class|func)\s+([A-Za-z_]\w*)").expect("regex")
    })
}

fn pyproject_guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*(?:\[[^\]]*)?tool\.(ruff|coverage)\b").expect("regex"))
}

fn ini_tool_guard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^\s*\[[^\]]*(?:tool[.:])?(ruff|coverage|flake8)\b").expect("regex")
    })
}

fn guard_surface_keys() -> &'static [(&'static str, Regex)] {
    static KEYS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    KEYS.get_or_init(|| {
        vec![
            (
                "ruff.toml",
                Regex::new(
                    r"^\s*(?:lint\.)?(?:extend|force-exclude|(?:extend-)?(?:select|ignore|exclude|include|fixable|unfixable|per-file-ignores))\s*=",
                )
                .expect("regex"),
            ),
            (
                "ruff.toml",
                Regex::new(r"^\s*\[[^\]]*per-file-ignores").expect("regex"),
            ),
            (
                "ruff.toml",
                Regex::new(r#"^\s*("[^"]+"|'[^']+')\s*="#).expect("regex"),
            ),
            (
                "ruff.toml",
                Regex::new(r#"^\s*(?:"[^"]+"|'[^']+')\s*,?\s*\]?\s*,?\s*(?:#.*)?$"#).expect("regex"),
            ),
            (
                "ruff.toml",
                Regex::new(r#"^\s*[A-Za-z0-9_.*/-]+\s*=\s*\[\s*["'][A-Z]+[0-9]*["']"#)
                    .expect("regex"),
            ),
            (
                ".coveragerc",
                Regex::new(
                    r"^\s*(fail_under|source|include|omit|exclude_lines|exclude_also|branch|skip_covered|skip_empty|ignore_errors|partial_branches|plugins)\s*[=:]",
                )
                .expect("regex"),
            ),
            (
                ".coveragerc",
                Regex::new(r"^\s+[^\s#;]").expect("regex"),
            ),
            (
                "tests/test_evals.py",
                Regex::new(r"\bROUTING_MIN_SCORE\s*=").expect("regex"),
            ),
            (
                "bench/vf-bench/gate.py",
                Regex::new(r"\bEXPECTED_VERSION\s*=").expect("regex"),
            ),
            (
                "bench/vf-bench/gate.py",
                Regex::new(r"\bEXPECTED_CANARY_GUID\s*=").expect("regex"),
            ),
            (
                "bench/vf-bench/gate.py",
                Regex::new(r"\bEXPECTED_CORPUS_SHA256\s*=").expect("regex"),
            ),
        ]
    })
}

pub fn is_media(path: &str) -> bool {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_ascii_lowercase()));
    ext.as_deref()
        .map(|e| BINARY_MEDIA.contains(&e))
        .unwrap_or(false)
}

pub fn is_coveragerc_section(text: &str) -> bool {
    text.trim_start().starts_with('[')
}

pub fn guard_surface_hit(path: &str, text: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    if GUARD_SURFACE_FILES.contains(&path) {
        return Some(path.to_string());
    }
    for dir in GUARD_SURFACE_DIRS {
        if path.starts_with(dir) {
            return Some(dir.trim_end_matches('/').to_string());
        }
    }
    let base = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if (base == "ruff.toml" || base == ".ruff.toml") && path != "ruff.toml" {
        return Some(path.to_string());
    }
    if base == "pyproject.toml" && pyproject_guard_re().is_match(text) {
        return Some(path.to_string());
    }
    if (base == "setup.cfg" || base == "tox.ini") && ini_tool_guard_re().is_match(text) {
        return Some(path.to_string());
    }
    if path == ".coveragerc" {
        let trimmed = text.trim();
        if trimmed.starts_with('[') && trimmed != "[run]" {
            return Some(".coveragerc".to_string());
        }
    }
    for (surface_file, pat) in guard_surface_keys() {
        if path == *surface_file && pat.is_match(text) {
            return Some((*surface_file).to_string());
        }
    }
    None
}

pub fn pyproject_guarded_sections(
    text: Option<&str>,
) -> Result<BTreeMap<String, toml::Value>, String> {
    let Some(src) = text else {
        return Ok(BTreeMap::new());
    };
    let data: toml::Value = toml::from_str(src).map_err(|e| format!("invalid TOML: {e}"))?;
    let mut out = BTreeMap::new();
    if let Some(tool) = data.get("tool").and_then(|v| v.as_table()) {
        for key in ["ruff", "coverage"] {
            if let Some(val) = tool.get(key) {
                out.insert(key.to_string(), val.clone());
            }
        }
    }
    Ok(out)
}

pub fn ini_guarded_sections(
    text: Option<&str>,
) -> Result<BTreeMap<String, Vec<(String, String)>>, String> {
    let Some(src) = text else {
        return Ok(BTreeMap::new());
    };
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut current_key: Option<String> = None;

    for raw_line in src.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if raw_line.starts_with('[') || trimmed.starts_with('[') {
            if !trimmed.ends_with(']') {
                return Err("malformed INI section header".to_string());
            }
            let sec = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            current = Some(sec.clone());
            current_key = None;
            sections.entry(sec).or_default();
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let (Some(sec), Some(k)) = (&current, &current_key) {
                if let Some(map) = sections.get_mut(sec) {
                    if let Some(val) = map.get_mut(k) {
                        val.push('\n');
                        val.push_str(trimmed);
                    }
                }
                continue;
            }
            return Err("unexpected INI continuation line".to_string());
        }
        let Some(sec) = &current else {
            return Err("INI key outside section".to_string());
        };
        let sep_idx = raw_line
            .find('=')
            .into_iter()
            .chain(raw_line.find(':'))
            .min()
            .ok_or_else(|| "malformed INI option line".to_string())?;
        let key = raw_line[..sep_idx].trim().to_ascii_lowercase();
        let val = raw_line[sep_idx + 1..].trim().to_string();
        sections
            .entry(sec.clone())
            .or_default()
            .insert(key.clone(), val);
        current_key = Some(key);
    }

    let guarded_exact: BTreeSet<&str> = [
        "flake8",
        "coverage",
        "ruff",
        "tool:ruff",
        "tool.ruff",
        "tool:coverage",
        "tool.coverage",
    ]
    .into_iter()
    .collect();
    let guarded_prefixes = [
        "flake8:",
        "coverage:",
        "ruff:",
        "tool:ruff:",
        "tool.ruff.",
        "tool:coverage:",
        "tool.coverage.",
    ];

    let mut out = BTreeMap::new();
    for (sec, kvs) in sections {
        let is_guarded = guarded_exact.contains(sec.as_str())
            || guarded_prefixes.iter().any(|p| sec.starts_with(p));
        if is_guarded {
            let mut pairs: Vec<(String, String)> = kvs
                .into_iter()
                .map(|(k, v)| (k, v.trim().to_string()))
                .collect();
            pairs.sort();
            out.insert(sec, pairs);
        }
    }
    Ok(out)
}
