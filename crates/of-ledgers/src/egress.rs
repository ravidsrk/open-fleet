//! Native Rust port of `runtime/scripts/egress.py`:
//! content-free, hash-chained receipts for off-repo sends.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FAIL_CLOSED: i32 = 3;
pub const EXIT_NO_RECEIPTS: i32 = 4;

pub const DEFAULT_LEDGER: &str = ".orca/egress.jsonl";
pub const PRIMARY_LEDGER_ENV: &str = "OPEN_FLEET_EGRESS_LEDGER";
pub const LEDGER_ENV: &str = "ORCA_EGRESS_LEDGER";
pub const FORMAT_VERSION: i64 = 2;
const MAX_FIELD_BYTES: usize = 512;
const READ_CHUNK: usize = 1 << 20;

const FIELDS: &[&str] = &[
    "ts",
    "sink",
    "host",
    "payload_class",
    "bytes",
    "payload_sha256",
    "consent",
    "prev",
];

const TEXT_FIELDS: &[&str] = &["sink", "host", "payload_class", "consent"];

pub const UNANCHORED: &str = "UNANCHORED: edits are caught, a rewrite is not — anchor this head and each id `write` printed off the writer, and pass them back as --expect-ancestor, or --expect-head for a sealed ledger";

fn text_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$").expect("regex"))
}

fn consent_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9 ._:/#()@+,=-]*[A-Za-z0-9._:/#()@+,=-])?$")
            .expect("regex")
    })
}

fn ts_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$",
        )
        .expect("regex")
    })
}

fn is_control_or_sep(c: char) -> bool {
    if c == ' ' {
        return false;
    }
    let u = c as u32;
    if u < 0x20 || (0x7f..=0x9f).contains(&u) {
        return true;
    }
    if matches!(
        u,
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    ) {
        return true;
    }
    // Format characters (Unicode Cf)
    of_common::decisions::has_invisible_cf(&c.to_string())
}

pub fn inert(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !is_control_or_sep(c) {
            out.push(c);
        } else {
            let u = c as u32;
            if u < 0x100 {
                out.push_str(&format!("\\x{u:02x}"));
            } else {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

fn eprint_inert(text: &str) {
    eprintln!("{}", inert(text));
}

fn print_inert(text: &str) {
    println!("{}", inert(text));
}

pub fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_hex(data: &str) -> String {
    sha256_hex_bytes(data.as_bytes())
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

fn lexists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn is_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
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

fn read_small_regular(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok_stat = unsafe { libc::fstat(fd, &mut st) } == 0;
        if !ok_stat || (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
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
        let meta = fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        let mut f = File::open(path).ok()?;
        let mut buf = [0u8; 4096];
        let n = f.read(&mut buf).ok()?;
        String::from_utf8(buf[..n].to_vec())
            .ok()
            .map(|s| s.trim().to_string())
    }
}

fn repositories(start: Option<&Path>) -> (Option<PathBuf>, Option<PathBuf>) {
    let here = match start {
        Some(p) => abspath(p),
        None => abspath(&env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
    };
    let mut found = Vec::new();
    let mut cur: Option<&Path> = Some(here.as_path());
    while let Some(d) = cur {
        if lexists(&d.join(".git")) {
            found.push(d.to_path_buf());
            if found.len() >= 2 {
                break;
            }
        }
        cur = d.parent();
    }
    let first = found.first().cloned();
    let second = found.get(1).cloned();
    (first, second)
}

fn linked_worktree_of(root: &Path, outer: &Path) -> bool {
    let gitfile = root.join(".git");
    let admin = outer.join(".git").join("worktrees");
    if is_symlink(&outer.join(".git")) {
        return false;
    }
    let Some(text) = read_small_regular(&gitfile) else {
        return false;
    };
    let Some(rest) = text.strip_prefix("gitdir:") else {
        return false;
    };
    let raw_target = PathBuf::from(rest.trim());
    let target_joined = if raw_target.is_absolute() {
        raw_target
    } else {
        root.join(raw_target)
    };
    let target = realpath_best_effort(&target_joined);
    let admin_real = realpath_best_effort(&admin);
    if target.parent() != Some(admin_real.as_path()) || !target.is_dir() {
        return false;
    }
    let Some(back_raw) = read_small_regular(&target.join("gitdir")) else {
        return false;
    };
    let back_p = PathBuf::from(&back_raw);
    let back_joined = if back_p.is_absolute() {
        back_p
    } else {
        target.join(back_p)
    };
    realpath_best_effort(&back_joined) == realpath_best_effort(&gitfile)
}

pub fn default_ledger(start: Option<&Path>) -> Result<(PathBuf, String), String> {
    let (root, outer) = repositories(start);
    let Some(root) = root else {
        let cwd = match start {
            Some(p) => abspath(p),
            None => abspath(&env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
        };
        return Err(format!(
            "no repository at or above {} (no .git): the default ledger is <repository root>/{DEFAULT_LEDGER}; run from inside the repository, or name the ledger with --ledger or ${PRIMARY_LEDGER_ENV}",
            cwd.display()
        ));
    };
    if let Some(outer) = outer {
        if !linked_worktree_of(&root, &outer) {
            return Err(format!(
                "the nearest repository root {} is nested inside the repository {} (a submodule, a vendored repository or a planted .git): refusing to pick a ledger silently; run from {}, or name the ledger with --ledger or ${PRIMARY_LEDGER_ENV}",
                root.display(),
                outer.display(),
                outer.display()
            ));
        }
        return Ok((
            root.join(DEFAULT_LEDGER),
            format!(
                "the default of linked worktree {}, inside the repository {}",
                root.display(),
                outer.display()
            ),
        ));
    }
    Ok((
        root.join(DEFAULT_LEDGER),
        "the repository default".to_string(),
    ))
}

pub fn resolve_ledger(explicit: Option<&Path>) -> Result<(PathBuf, String), String> {
    if let Some(p) = explicit {
        return Ok((abspath(p), "--ledger".to_string()));
    }
    for var in [PRIMARY_LEDGER_ENV, LEDGER_ENV] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                return Ok((abspath(Path::new(&val)), format!("${var}")));
            }
        }
    }
    default_ledger(None)
}

fn routing_note(path: &Path, source: &str) -> Option<String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let via_link = is_symlink(parent);
    if source == "the repository default" && !via_link {
        return None;
    }
    if source.starts_with("the default of linked worktree") && !via_link {
        return Some(format!(
            "egress: receipt written to {}: {source}, not to that repository's ledger",
            path.display()
        ));
    }
    let (default_path, default_source) = match default_ledger(None) {
        Ok((p, s)) => (Some(p), Some(s)),
        Err(_) => (None, None),
    };
    if default_path.as_deref() == Some(path)
        && default_source.as_deref() == Some("the repository default")
        && !via_link
    {
        return None;
    }
    let real = realpath_best_effort(path);
    let real_parent = real
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let where_str = if via_link {
        format!(
            "{} ({source}, its directory a symlink to {real_parent})",
            path.display()
        )
    } else {
        format!("{} ({source})", path.display())
    };
    let other = match (&default_path, default_source.as_deref()) {
        (None, _) => "no repository ledger to compare (the default refuses here)".to_string(),
        (Some(dp), Some("the repository default")) => {
            format!("not the repository ledger {}", dp.display())
        }
        (Some(_), Some(ds)) => format!("{ds}, not that repository's ledger"),
        (Some(_), None) => "no repository ledger to compare (the default refuses here)".to_string(),
    };
    Some(format!("egress: receipt written to {where_str}; {other}"))
}

pub fn valid_ts(value: &str) -> Result<(), String> {
    if !ts_pattern().is_match(value) {
        return Err(format!(
            "ts must be ISO-8601 like 2026-01-02T03:04:05Z, got {value:?}"
        ));
    }
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| format!("ts must be ISO-8601 like 2026-01-02T03:04:05Z, got {value:?}"))?;
    Ok(())
}

fn json_escape_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone)]
pub struct EgressRecord {
    pub version: i64,
    pub id: String,
    pub ts: String,
    pub sink: String,
    pub host: String,
    pub payload_class: String,
    pub bytes: u64,
    pub payload_sha256: Option<String>,
    pub consent: String,
    pub prev: String,
}

impl EgressRecord {
    fn payload_sha_json(&self) -> String {
        match &self.payload_sha256 {
            Some(s) => json_escape_ascii(s),
            None => "null".to_string(),
        }
    }

    pub fn compute_id(&self) -> String {
        if self.version == FORMAT_VERSION {
            let body = format!(
                "{{\"v\":{},\"ts\":{},\"sink\":{},\"host\":{},\"payload_class\":{},\"bytes\":{},\"payload_sha256\":{},\"consent\":{},\"prev\":{}}}",
                FORMAT_VERSION,
                json_escape_ascii(&self.ts),
                json_escape_ascii(&self.sink),
                json_escape_ascii(&self.host),
                json_escape_ascii(&self.payload_class),
                self.bytes,
                self.payload_sha_json(),
                json_escape_ascii(&self.consent),
                json_escape_ascii(&self.prev),
            );
            sha256_hex(&body)
        } else {
            let psha = self.payload_sha256.as_deref().unwrap_or("");
            let joined = format!(
                "ts={}\nsink={}\nhost={}\npayload_class={}\nbytes={}\npayload_sha256={}\nconsent={}\nprev={}",
                self.ts,
                self.sink,
                self.host,
                self.payload_class,
                self.bytes,
                psha,
                self.consent,
                self.prev,
            );
            sha256_hex(&joined)
        }
    }

    pub fn canonical_line(&self) -> String {
        if self.version == FORMAT_VERSION {
            format!(
                "{{\"v\":{},\"id\":{},\"ts\":{},\"sink\":{},\"host\":{},\"payload_class\":{},\"bytes\":{},\"payload_sha256\":{},\"consent\":{},\"prev\":{}}}",
                FORMAT_VERSION,
                json_escape_ascii(&self.id),
                json_escape_ascii(&self.ts),
                json_escape_ascii(&self.sink),
                json_escape_ascii(&self.host),
                json_escape_ascii(&self.payload_class),
                self.bytes,
                self.payload_sha_json(),
                json_escape_ascii(&self.consent),
                json_escape_ascii(&self.prev),
            )
        } else {
            format!(
                "{{\"id\":{},\"ts\":{},\"sink\":{},\"host\":{},\"payload_class\":{},\"bytes\":{},\"payload_sha256\":{},\"consent\":{},\"prev\":{}}}",
                json_escape_ascii(&self.id),
                json_escape_ascii(&self.ts),
                json_escape_ascii(&self.sink),
                json_escape_ascii(&self.host),
                json_escape_ascii(&self.payload_class),
                self.bytes,
                self.payload_sha_json(),
                json_escape_ascii(&self.consent),
                json_escape_ascii(&self.prev),
            )
        }
    }
}

pub fn require_field(value: &str, name: &str, grant_shape: bool) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(format!("receipt requires a non-empty {name}"));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(format!(
            "receipt {name} may not contain a newline (one receipt, one line)"
        ));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(format!("receipt {name} exceeds {MAX_FIELD_BYTES} bytes"));
    }
    if !text_pattern().is_match(value) {
        return Err(format!(
            "receipt {name} must be printable ASCII with no leading or trailing space: {value:?}"
        ));
    }
    if grant_shape && name == "consent" && !consent_pattern().is_match(value) {
        return Err(format!(
            "receipt consent must name a grant (letters, digits and ` ._:/#()@+,=-`, starting with a letter or digit, e.g. grant:pr-open-on-base): {value:?}"
        ));
    }
    Ok(value.to_string())
}

fn validate_json_line(
    raw: &str,
    parsed: Option<&Value>,
    previous_raw: Option<&str>,
) -> Result<EgressRecord, String> {
    let Some(Value::Object(map)) = parsed else {
        return Err("unparseable line or missing prev".to_string());
    };
    let Some(Value::String(prev)) = map.get("prev") else {
        return Err("unparseable line or missing prev".to_string());
    };
    let expected_prev = match previous_raw {
        None => String::new(),
        Some(p) => sha256_hex(p),
    };
    if prev != &expected_prev {
        return Err("prev does not match the previous raw line".to_string());
    }
    let version = if let Some(v_val) = map.get("v") {
        if v_val.as_i64() == Some(FORMAT_VERSION) && v_val.is_i64() {
            FORMAT_VERSION
        } else {
            return Err(format!("unknown format version {v_val}"));
        }
    } else {
        1
    };

    let expected_keys: BTreeSet<&str> = if version == FORMAT_VERSION {
        ["v", "id"]
            .into_iter()
            .chain(FIELDS.iter().copied())
            .collect()
    } else {
        ["id"].into_iter().chain(FIELDS.iter().copied()).collect()
    };
    let actual_keys: BTreeSet<&str> = map.keys().map(|k| k.as_str()).collect();
    if actual_keys != expected_keys {
        let extra: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        let prefix = if !extra.is_empty() {
            format!("unknown key(s) {}", extra.join(", "))
        } else {
            format!("missing key(s) {}", missing.join(", "))
        };
        return Err(format!(
            "{prefix} — a receipt holds exactly its fields, so every byte of it is bound"
        ));
    }

    for k in FIELDS {
        if let Some(Value::String(sv)) = map.get(*k) {
            if sv.contains('\n') || sv.contains('\r') {
                return Err("a field carries a line break (ambiguous id encoding)".to_string());
            }
        }
    }

    let ts = match map.get("ts") {
        Some(Value::String(s)) if valid_ts(s).is_ok() => s.clone(),
        _ => return Err("ts is not an ISO-8601 instant with an offset".to_string()),
    };

    for name in TEXT_FIELDS {
        let Some(Value::String(sv)) = map.get(*name) else {
            return Err(format!("receipt requires a non-empty {name}"));
        };
        require_field(sv, name, version == FORMAT_VERSION)?;
    }

    let bytes = match map.get("bytes") {
        Some(Value::Number(n)) => {
            if let Some(u) = n.as_u64() {
                u
            } else {
                return Err("bytes is not a non-negative integer".to_string());
            }
        }
        _ => return Err("bytes is not a non-negative integer".to_string()),
    };

    let payload_sha256 = match map.get("payload_sha256") {
        Some(Value::Null) => None,
        Some(Value::String(s)) if is_sha256(s) => Some(s.clone()),
        _ => return Err("payload_sha256 is neither null nor a sha256".to_string()),
    };

    let id = match map.get("id") {
        Some(Value::String(s)) if is_sha256(s) => s.clone(),
        _ => return Err("id is not a sha256".to_string()),
    };

    let rec = EgressRecord {
        version,
        id,
        ts,
        sink: map["sink"].as_str().unwrap_or("").to_string(),
        host: map["host"].as_str().unwrap_or("").to_string(),
        payload_class: map["payload_class"].as_str().unwrap_or("").to_string(),
        bytes,
        payload_sha256,
        consent: map["consent"].as_str().unwrap_or("").to_string(),
        prev: prev.clone(),
    };

    if raw != rec.canonical_line() {
        return Err(
            "the line is not the canonical serialisation of its record (a byte no hash binds)"
                .to_string(),
        );
    }
    if rec.id != rec.compute_id() {
        return Err("id does not match the record's own fields".to_string());
    }
    Ok(rec)
}

pub struct ScanResult {
    pub receipts: Vec<(usize, String, EgressRecord)>,
    pub broken_line: Option<usize>,
    pub reason: Option<String>,
    pub lines_read: usize,
}

pub fn scan(data: &[u8]) -> ScanResult {
    if data.is_empty() {
        return ScanResult {
            receipts: Vec::new(),
            broken_line: None,
            reason: None,
            lines_read: 0,
        };
    }
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(err) => {
            let start = err.valid_up_to();
            let lineno = data[..start].iter().filter(|&&b| b == b'\n').count() + 1;
            let total = data.iter().filter(|&&b| b == b'\n').count() + 1;
            return ScanResult {
                receipts: Vec::new(),
                broken_line: Some(lineno),
                reason: Some(format!("not valid UTF-8 (invalid byte at byte {start})")),
                lines_read: total,
            };
        }
    };
    let parts: Vec<&str> = text.split('\n').collect();
    let total = if parts.last() == Some(&"") {
        parts.len() - 1
    } else {
        parts.len()
    };
    let mut receipts = Vec::new();
    let mut previous_raw: Option<String> = None;
    let mut seen_v2 = false;

    for (idx, &raw) in parts[..parts.len() - 1].iter().enumerate() {
        let lineno = idx + 1;
        if raw.is_empty() {
            return ScanResult {
                receipts,
                broken_line: Some(lineno),
                reason: Some(
                    "an empty line (every byte of the ledger belongs to a receipt)".to_string(),
                ),
                lines_read: total,
            };
        }
        let parsed: Option<Value> = serde_json::from_str(raw).ok();
        let rec = match validate_json_line(raw, parsed.as_ref(), previous_raw.as_deref()) {
            Ok(r) => r,
            Err(why) => {
                return ScanResult {
                    receipts,
                    broken_line: Some(lineno),
                    reason: Some(why),
                    lines_read: total,
                };
            }
        };
        if rec.version == FORMAT_VERSION {
            seen_v2 = true;
        } else if seen_v2 {
            return ScanResult {
                receipts,
                broken_line: Some(lineno),
                reason: Some(
                    "a legacy (v1) receipt after a v2 one: only the v2 writer appends".to_string(),
                ),
                lines_read: total,
            };
        }
        receipts.push((lineno, raw.to_string(), rec));
        previous_raw = Some(raw.to_string());
    }

    if !parts.last().copied().unwrap_or("").is_empty() {
        return ScanResult {
            receipts,
            broken_line: Some(total),
            reason: Some(
                "the last line has no terminating newline (a torn write, or bytes appended after the last receipt)".to_string(),
            ),
            lines_read: total,
        };
    }

    ScanResult {
        receipts,
        broken_line: None,
        reason: None,
        lines_read: total,
    }
}

#[cfg(unix)]
fn read_all_fd(fd: libc::c_int) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut offset: libc::off_t = 0;
    loop {
        let n =
            unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
        offset += n as libc::off_t;
    }
    Ok(out)
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> Result<(), std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fsync(fd) };
    let err = if rc < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(fd) };
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(unix)]
fn same_file(path: &Path, st: &libc::stat) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("receipt ledger {} has NUL byte", path.display()))?;
    let mut now_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(cpath.as_ptr(), &mut now_st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "receipt ledger {} vanished while it was being written: {err}",
            path.display()
        ));
    }
    if (now_st.st_dev, now_st.st_ino) != (st.st_dev, st.st_ino) {
        return Err(format!(
            "receipt ledger {} was replaced while it was being written; no receipt is on the ledger that name now names",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_for_append(path: &Path) -> Result<(libc::c_int, bool), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("invalid path {}", path.display()))?;
    let flags =
        libc::O_RDWR | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd >= 0 {
        return Ok((fd, false));
    }
    let err = std::io::Error::last_os_error();
    if err.kind() != std::io::ErrorKind::NotFound {
        return Err(format!(
            "receipt could not be written to {}: {err}",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !lexists(parent) {
        let cparent = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| format!("invalid dir {}", parent.display()))?;
        let mk = unsafe { libc::mkdir(cparent.as_ptr(), 0o700) };
        if mk != 0 {
            let merr = std::io::Error::last_os_error();
            match merr.kind() {
                std::io::ErrorKind::AlreadyExists => {}
                std::io::ErrorKind::NotFound => {
                    return Err(format!(
                        "the ledger's directory {} does not exist and neither does its parent: egress.py creates the ledger's own directory, never a tree above it",
                        parent.display()
                    ));
                }
                _ => {
                    return Err(format!(
                        "receipt could not be written to {}: {merr}",
                        path.display()
                    ));
                }
            }
        } else if let Some(grand) = parent.parent() {
            if !grand.as_os_str().is_empty() {
                fsync_dir(grand).map_err(|e| {
                    format!("receipt could not be written to {}: {e}", path.display())
                })?;
            }
        }
    }
    let fd_new = unsafe { libc::open(cpath.as_ptr(), flags | libc::O_CREAT | libc::O_EXCL, 0o600) };
    if fd_new >= 0 {
        return Ok((fd_new, true));
    }
    let cerr = std::io::Error::last_os_error();
    if cerr.kind() == std::io::ErrorKind::AlreadyExists {
        let fd_retry = unsafe { libc::open(cpath.as_ptr(), flags) };
        if fd_retry >= 0 {
            return Ok((fd_retry, false));
        }
        let rerr = std::io::Error::last_os_error();
        return Err(format!(
            "receipt could not be written to {}: {rerr}",
            path.display()
        ));
    }
    Err(format!(
        "receipt could not be written to {}: {cerr}",
        path.display()
    ))
}

pub struct WriteReceiptParams<'a> {
    pub path: &'a Path,
    pub sink: &'a str,
    pub host: &'a str,
    pub payload_class: &'a str,
    pub consent: &'a str,
    pub nbytes: u64,
    pub payload_sha256: Option<&'a str>,
    pub ts: Option<&'a str>,
}

pub fn write_receipt(params: &WriteReceiptParams<'_>) -> Result<EgressRecord, String> {
    let path = params.path;
    let nbytes = params.nbytes;
    let payload_sha256 = params.payload_sha256;
    let ts = params.ts;
    if let Some(t) = ts {
        valid_ts(t)?;
    }
    let sink = require_field(params.sink, "sink", true)?;
    let host = require_field(params.host, "host", true)?;
    let payload_class = require_field(params.payload_class, "payload_class", true)?;
    let consent = require_field(params.consent, "consent", true)?;
    if let Some(ps) = payload_sha256 {
        if !is_sha256(ps) {
            return Err("payload_sha256 must be 64 lowercase hex characters or absent".to_string());
        }
    }
    let ts_str = match ts {
        Some(t) => t.to_string(),
        None => Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };

    #[cfg(unix)]
    {
        let (fd, created) = open_for_append(path)?;
        let res = (|| -> Result<EgressRecord, String> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!(
                    "receipt could not be written to {}: {err}",
                    path.display()
                ));
            }
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(format!(
                    "receipt ledger {} is not a regular file",
                    path.display()
                ));
            }
            if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!(
                    "receipt could not be written to {}: {err}",
                    path.display()
                ));
            }
            same_file(path, &st)?;
            let data = read_all_fd(fd)
                .map_err(|e| format!("receipt could not be written to {}: {e}", path.display()))?;
            let scanned = scan(&data);
            if let Some(broken) = scanned.broken_line {
                let reason = scanned.reason.unwrap_or_default();
                return Err(format!(
                    "{}:{broken} fails verification ({reason}); refusing to chain a receipt onto a ledger the verifier refuses. Repair it, and record why, before sending",
                    path.display()
                ));
            }
            let prev = scanned
                .receipts
                .last()
                .map(|(_, raw, _)| sha256_hex(raw))
                .unwrap_or_default();
            let mut rec = EgressRecord {
                version: FORMAT_VERSION,
                id: String::new(),
                ts: ts_str,
                sink,
                host,
                payload_class,
                bytes: nbytes,
                payload_sha256: payload_sha256.map(|s| s.to_string()),
                consent,
                prev,
            };
            rec.id = rec.compute_id();
            let line = format!("{}\n", rec.canonical_line());
            let bytes = line.as_bytes();
            let mut written = 0usize;
            while written < bytes.len() {
                let n = unsafe {
                    libc::write(
                        fd,
                        bytes[written..].as_ptr() as *const libc::c_void,
                        bytes.len() - written,
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    unsafe { libc::ftruncate(fd, data.len() as libc::off_t) };
                    return Err(format!(
                        "receipt could not be written to {}: {err}",
                        path.display()
                    ));
                }
                written += n as usize;
            }
            if unsafe { libc::fsync(fd) } != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::ftruncate(fd, data.len() as libc::off_t) };
                return Err(format!(
                    "receipt could not be written to {}: {err}",
                    path.display()
                ));
            }
            if created {
                if let Some(parent) = path.parent() {
                    fsync_dir(parent).map_err(|e| {
                        format!("receipt could not be written to {}: {e}", path.display())
                    })?;
                }
            }
            same_file(path, &st)?;
            Ok(rec)
        })();
        unsafe { libc::close(fd) };
        res
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir(parent).map_err(|e| {
                    format!(
                        "the ledger's directory {} does not exist and could not be created: {e}",
                        parent.display()
                    )
                })?;
            }
        }
        let data = if path.exists() {
            fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?
        } else {
            Vec::new()
        };
        let scanned = scan(&data);
        if let Some(broken) = scanned.broken_line {
            let reason = scanned.reason.unwrap_or_default();
            return Err(format!(
                "{}:{broken} fails verification ({reason}); refusing to chain a receipt onto a ledger the verifier refuses. Repair it, and record why, before sending",
                path.display()
            ));
        }
        let prev = scanned
            .receipts
            .last()
            .map(|(_, raw, _)| sha256_hex(raw))
            .unwrap_or_default();
        let mut rec = EgressRecord {
            version: FORMAT_VERSION,
            id: String::new(),
            ts: ts_str,
            sink,
            host,
            payload_class,
            bytes: nbytes,
            payload_sha256: payload_sha256.map(|s| s.to_string()),
            consent,
            prev,
        };
        rec.id = rec.compute_id();
        let line = format!("{}\n", rec.canonical_line());
        let mut fh = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("receipt could not be written to {}: {e}", path.display()))?;
        fh.write_all(line.as_bytes())
            .and_then(|_| fh.sync_all())
            .map_err(|e| format!("receipt could not be written to {}: {e}", path.display()))?;
        Ok(rec)
    }
}

pub struct LoadedLedger {
    pub exists: bool,
    pub scan: ScanResult,
}

pub fn load_ledger(path: &Path) -> Result<LoadedLedger, String> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("{} is unreadable", path.display()))?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(LoadedLedger {
                    exists: false,
                    scan: scan(&[]),
                });
            }
            return Err(format!(
                "{} is unreadable (a symlinked ledger is refused): {err}",
                path.display()
            ));
        }
        let res = (|| -> Result<Vec<u8>, String> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("{} is unreadable: {err}", path.display()));
            }
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(format!("{} is not a regular file", path.display()));
            }
            if unsafe { libc::flock(fd, libc::LOCK_SH) } != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("{} is unreadable: {err}", path.display()));
            }
            read_all_fd(fd).map_err(|e| format!("{} is unreadable: {e}", path.display()))
        })();
        unsafe { libc::close(fd) };
        let data = res?;
        Ok(LoadedLedger {
            exists: true,
            scan: scan(&data),
        })
    }

    #[cfg(not(unix))]
    {
        if !path.exists() {
            return Ok(LoadedLedger {
                exists: false,
                scan: scan(&[]),
            });
        }
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("{} is unreadable: {e}", path.display()))?;
        if !meta.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let data = fs::read(path).map_err(|e| format!("{} is unreadable: {e}", path.display()))?;
        Ok(LoadedLedger {
            exists: true,
            scan: scan(&data),
        })
    }
}

pub fn hash_file(path: &Path) -> Result<(String, u64), std::io::Error> {
    let mut fh = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut count = 0u64;
    loop {
        let n = fh.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        count += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), count))
}

fn anchored_value(raw: &str) -> String {
    let want = raw.trim().to_ascii_lowercase();
    if want == "(empty)" {
        String::new()
    } else {
        want
    }
}

pub fn valid_anchor_value(raw: &str) -> bool {
    let cleaned = raw.trim().to_ascii_lowercase();
    cleaned == "(empty)" || is_sha256(&cleaned)
}

fn emit_tamper(path: &Path, broken: usize, reason: &str, count: usize) -> i32 {
    eprint_inert(&format!(
        "egress: TAMPER at {}:{broken} — {reason} ({count} line(s) read)",
        path.display()
    ));
    EXIT_FAIL_CLOSED
}

fn anchors_fail(
    expect_head: Option<&str>,
    expect_ancestors: &[String],
    path: &Path,
    exists: bool,
    receipts: &[(usize, String, EgressRecord)],
) -> Option<i32> {
    for raw in expect_ancestors {
        if !valid_anchor_value(raw) {
            eprint_inert(&format!(
                "egress: invalid --expect-ancestor value {raw:?}: must be a 64-character hex sha256 or '(empty)'"
            ));
            return Some(EXIT_USAGE);
        }
    }
    if let Some(exp) = expect_head {
        if !valid_anchor_value(exp) {
            eprint_inert(&format!(
                "egress: invalid --expect-head value {exp:?}: must be a 64-character hex sha256 or '(empty)'"
            ));
            return Some(EXIT_USAGE);
        }
    }
    let head = receipts
        .last()
        .map(|(_, raw, _)| sha256_hex(raw))
        .unwrap_or_default();
    let shown = if head.is_empty() {
        "(empty)".to_string()
    } else {
        head.clone()
    };
    let mut known: HashSet<String> = HashSet::new();
    for (_, raw, rec) in receipts {
        known.insert(sha256_hex(raw));
        known.insert(rec.id.clone());
    }
    for raw in expect_ancestors {
        let want = anchored_value(raw);
        if !want.is_empty() && !known.contains(&want) {
            let gone = if !exists {
                "there is no ledger file at all"
            } else {
                "a rewritten or truncated ledger loses the anchored line"
            };
            eprint_inert(&format!(
                "egress: TAMPER at {} — the anchored receipt {want} is not in this chain ({gone}). Appends since the anchor are fine; this is what an anchor kept off the writer catches (#312)",
                path.display()
            ));
            return Some(EXIT_FAIL_CLOSED);
        }
    }
    if let Some(exp) = expect_head {
        let want = anchored_value(exp);
        let mut last: HashSet<String> = HashSet::new();
        if let Some((_, _, rec)) = receipts.last() {
            last.insert(head);
            last.insert(rec.id.clone());
        } else {
            last.insert(String::new());
        }
        if !last.contains(&want) {
            let want_shown = if want.is_empty() { "(empty)" } else { &want };
            eprint_inert(&format!(
                "egress: TAMPER at {} — the chain is internally intact, but its head is {shown}, not the anchored {want_shown}. A ledger rewritten from scratch chains perfectly to its own new genesis, so recomputing the chain can never catch that; only a head kept where the writer cannot reach it can (#312)",
                path.display()
            ));
            return Some(EXIT_FAIL_CLOSED);
        }
    }
    None
}

pub struct WriteArgs {
    pub ledger: Option<PathBuf>,
    pub sink: String,
    pub host: String,
    pub payload_class: String,
    pub consent: String,
    pub bytes: Option<i64>,
    pub payload_file: Option<PathBuf>,
    pub payload_sha256: Option<String>,
    pub ts: Option<String>,
}

pub fn cmd_write(args: &WriteArgs) -> i32 {
    if let Some(t) = args.ts.as_deref() {
        if let Err(err) = valid_ts(t) {
            eprint_inert(&format!("egress: {err}"));
            return EXIT_USAGE;
        }
    }
    let (path, source) = match resolve_ledger(args.ledger.as_deref()) {
        Ok(v) => v,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    let mut payload_sha = args.payload_sha256.clone();
    let mut nbytes = args.bytes;
    if let Some(pf) = args.payload_file.as_deref() {
        match hash_file(pf) {
            Ok((digest, size)) => {
                payload_sha = Some(digest);
                if nbytes.is_none() {
                    nbytes = Some(size as i64);
                }
            }
            Err(err) => {
                eprint_inert(&format!("egress: payload file unreadable: {err}"));
                return EXIT_USAGE;
            }
        }
    }
    let final_bytes = match nbytes {
        Some(b) if b < 0 => {
            eprint_inert(
                "egress: EGRESS_RECEIPT_FAILED: receipt bytes must be a non-negative integer",
            );
            return EXIT_FAIL_CLOSED;
        }
        Some(b) => b as u64,
        None => 0,
    };
    let rec = match write_receipt(&WriteReceiptParams {
        path: &path,
        sink: &args.sink,
        host: &args.host,
        payload_class: &args.payload_class,
        consent: &args.consent,
        nbytes: final_bytes,
        payload_sha256: payload_sha.as_deref(),
        ts: args.ts.as_deref(),
    }) {
        Ok(r) => r,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    if let Some(note) = routing_note(&path, &source) {
        eprint_inert(&note);
    }
    print_inert(&rec.id);
    EXIT_OK
}

pub struct VerifyArgs {
    pub ledger: Option<PathBuf>,
    pub expect_head: Option<String>,
    pub expect_ancestor: Vec<String>,
    pub allow_empty: bool,
}

pub fn cmd_verify(args: &VerifyArgs) -> i32 {
    let (path, source) = match resolve_ledger(args.ledger.as_deref()) {
        Ok(v) => v,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    let loaded = match load_ledger(&path) {
        Ok(l) => l,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    if let Some(broken) = loaded.scan.broken_line {
        return emit_tamper(
            &path,
            broken,
            loaded.scan.reason.as_deref().unwrap_or(""),
            loaded.scan.lines_read,
        );
    }
    let receipts = &loaded.scan.receipts;
    let count = receipts.len();
    let head = receipts
        .last()
        .map(|(_, raw, _)| sha256_hex(raw))
        .unwrap_or_default();
    let shown = if head.is_empty() {
        "(empty)".to_string()
    } else {
        head.clone()
    };
    let where_str = if loaded.exists {
        format!("{} ({source})", path.display())
    } else {
        format!("{} ({source}) — no ledger file there", path.display())
    };
    if let Some(code) = anchors_fail(
        args.expect_head.as_deref(),
        &args.expect_ancestor,
        &path,
        loaded.exists,
        receipts,
    ) {
        return code;
    }
    let sealed_empty = args
        .expect_head
        .as_deref()
        .map(|e| anchored_value(e).is_empty())
        .unwrap_or(false);
    let real_head = args
        .expect_head
        .as_deref()
        .map(|e| is_sha256(&anchored_value(e)))
        .unwrap_or(false);
    let real_ancestors: Vec<String> = args
        .expect_ancestor
        .iter()
        .map(|a| anchored_value(a))
        .filter(|v| is_sha256(v))
        .collect();

    if count == 0 && !sealed_empty {
        if !args.allow_empty {
            print_inert(&format!(
                "egress: NO RECEIPTS, 0 receipt(s) in {where_str} — nothing was verified"
            ));
            eprint_inert(&format!(
                "egress: NO RECEIPTS in {where_str} — a close that expects receipts must find them here; if this run sent nothing, say so with --allow-empty"
            ));
            return EXIT_NO_RECEIPTS;
        }
        print_inert(&format!(
            "egress: NO RECEIPTS, 0 receipt(s) in {where_str} — none expected (--allow-empty)"
        ));
        return EXIT_OK;
    }
    if real_head || (sealed_empty && count == 0) {
        print_inert(&format!(
            "egress: chain intact and anchored, {count} receipt(s) in {where_str} — head {shown}"
        ));
        return EXIT_OK;
    }
    if !real_ancestors.is_empty() {
        print_inert(&format!(
            "egress: chain intact, anchored receipt(s) present, {count} receipt(s) in {where_str} — head {shown}"
        ));
        return EXIT_OK;
    }
    print_inert(&format!(
        "egress: chain intact, {count} receipt(s) in {where_str} — head {shown} ({UNANCHORED})"
    ));
    EXIT_OK
}

pub fn cmd_head(ledger: Option<&Path>) -> i32 {
    let (path, _source) = match resolve_ledger(ledger) {
        Ok(v) => v,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    let loaded = match load_ledger(&path) {
        Ok(l) => l,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    if let Some(broken) = loaded.scan.broken_line {
        return emit_tamper(
            &path,
            broken,
            loaded.scan.reason.as_deref().unwrap_or(""),
            loaded.scan.lines_read,
        );
    }
    let out = loaded
        .scan
        .receipts
        .last()
        .map(|(_, raw, _)| sha256_hex(raw))
        .unwrap_or_else(|| "(empty)".to_string());
    print_inert(&out);
    EXIT_OK
}

pub struct GrantsArgs {
    pub ledger: Option<PathBuf>,
    pub json: bool,
    pub expect_head: Option<String>,
    pub expect_ancestor: Vec<String>,
}

pub fn cmd_grants(args: &GrantsArgs) -> i32 {
    let (path, _source) = match resolve_ledger(args.ledger.as_deref()) {
        Ok(v) => v,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    let loaded = match load_ledger(&path) {
        Ok(l) => l,
        Err(err) => {
            eprint_inert(&format!("egress: EGRESS_RECEIPT_FAILED: {err}"));
            return EXIT_FAIL_CLOSED;
        }
    };
    if let Some(broken) = loaded.scan.broken_line {
        return emit_tamper(
            &path,
            broken,
            loaded.scan.reason.as_deref().unwrap_or(""),
            loaded.scan.lines_read,
        );
    }
    let receipts = &loaded.scan.receipts;
    if let Some(code) = anchors_fail(
        args.expect_head.as_deref(),
        &args.expect_ancestor,
        &path,
        loaded.exists,
        receipts,
    ) {
        return code;
    }
    let real_ancestors = args
        .expect_ancestor
        .iter()
        .any(|a| is_sha256(&anchored_value(a)));
    let real_head = args
        .expect_head
        .as_deref()
        .map(|e| is_sha256(&anchored_value(e)))
        .unwrap_or(false);
    let sealed_empty = args
        .expect_head
        .as_deref()
        .map(|e| anchored_value(e).is_empty())
        .unwrap_or(false)
        && receipts.is_empty();
    let anchored = real_ancestors || real_head || sealed_empty;

    struct GrantAgg {
        uses: usize,
        sinks: BTreeSet<String>,
        hosts: BTreeSet<String>,
    }
    let mut grants: BTreeMap<String, GrantAgg> = BTreeMap::new();
    for (_, _, rec) in receipts {
        let entry = grants
            .entry(rec.consent.clone())
            .or_insert_with(|| GrantAgg {
                uses: 0,
                sinks: BTreeSet::new(),
                hosts: BTreeSet::new(),
            });
        entry.uses += 1;
        if !rec.sink.is_empty() {
            entry.sinks.insert(rec.sink.clone());
        }
        if !rec.host.is_empty() {
            entry.hosts.insert(rec.host.clone());
        }
    }

    if args.json {
        let rows: Vec<Value> = grants
            .iter()
            .map(|(consent, agg)| {
                serde_json::json!({
                    "consent": consent,
                    "uses": agg.uses,
                    "sinks": agg.sinks.iter().collect::<Vec<_>>(),
                    "hosts": agg.hosts.iter().collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        if grants.is_empty() {
            print_inert(&format!(
                "egress: no consents recorded in {}",
                path.display()
            ));
        }
        for (consent, agg) in &grants {
            let sinks: Vec<&str> = agg.sinks.iter().map(|s| s.as_str()).collect();
            let hosts: Vec<&str> = agg.hosts.iter().map(|s| s.as_str()).collect();
            print_inert(&format!(
                "{consent}  uses={}  sinks={}  hosts={}",
                agg.uses,
                sinks.join(","),
                hosts.join(",")
            ));
        }
    }
    if !anchored {
        let msg = format!(
            "egress: these consents come from a chain checked only against itself ({UNANCHORED})"
        );
        if args.json {
            eprint_inert(&msg);
        } else {
            print_inert(&msg);
        }
    }
    EXIT_OK
}
