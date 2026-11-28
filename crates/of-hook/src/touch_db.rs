//! Native SQLite WAL file-touch conflict recorder for `of-hook` — port of
//! `runtime/scripts/deny-hook.sh` `L5839-6043` and `runtime/providers/local_state.py` schema v2.

use crate::path_guard;
use crate::types::{HookConfig, ParsedPayload};
use regex::Regex;
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: i32 = 2;
const BUSY_TIMEOUT_MS: u64 = 30_000;
const WHOLE_RANGE: (i64, i64) = (1, 999_999);
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;

const OLD_KEYS: &[&str] = &["old_string", "old_str", "oldString", "oldText", "old_text"];
const TOP_PATH_KEYS: &[&str] = &["file_path", "path", "filePath", "notebook_path"];
const EDIT_PATH_KEYS: &[&str] = &["file_path", "path", "filePath"];

const SCHEMA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    coordinator_handle TEXT,
    objective TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT 'default',
    title TEXT,
    display_name TEXT,
    spec TEXT NOT NULL,
    status TEXT NOT NULL,
    parent_id TEXT,
    result_json TEXT,
    sender TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS task_deps (
    task_id TEXT NOT NULL,
    dep_id TEXT NOT NULL,
    PRIMARY KEY (task_id, dep_id)
);
CREATE TABLE IF NOT EXISTS dispatches (
    dispatch_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT 'default',
    worktree TEXT NOT NULL,
    agent TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'rw',
    terminal_handle TEXT NOT NULL,
    state TEXT NOT NULL,
    terminal_state TEXT NOT NULL DEFAULT 'active',
    pid INTEGER,
    backend TEXT DEFAULT 'setsid',
    launch_effective TEXT,
    lane_dir TEXT,
    session_id TEXT,
    backend_ref TEXT,
    head_sha TEXT,
    monitor_pid INTEGER,
    monitor_started_at REAL,
    intent_id TEXT,
    gate_closed_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS terminals (
    handle TEXT PRIMARY KEY,
    worktree TEXT,
    title TEXT,
    command TEXT,
    shell TEXT,
    pid INTEGER,
    backend TEXT DEFAULT 'setsid',
    backend_ref TEXT,
    log_path TEXT,
    state TEXT NOT NULL DEFAULT 'running',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT 'default',
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    msg_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    outcome TEXT,
    payload TEXT,
    attrs_json TEXT,
    reply_to TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT 'default',
    acked INTEGER NOT NULL DEFAULT 0,
    acked_at REAL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS gates (
    gate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT 'default',
    sender TEXT,
    recipient TEXT,
    question TEXT NOT NULL,
    options_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    answer TEXT,
    task_id TEXT,
    message_id TEXT,
    prev_status TEXT,
    kind TEXT DEFAULT 'ask',
    created_at REAL NOT NULL,
    resolved_at REAL
);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    state TEXT NOT NULL,
    response_json TEXT,
    created_at REAL NOT NULL,
    payload_sha256 TEXT,
    intent_id TEXT,
    claim_pid INTEGER,
    claim_host TEXT,
    caller_scope TEXT,
    contacted_runtime INTEGER NOT NULL DEFAULT 0,
    claimed_task_id TEXT
);
CREATE TABLE IF NOT EXISTS file_touches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL DEFAULT 'default',
    worker_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL DEFAULT 1,
    end_line INTEGER NOT NULL DEFAULT 999999,
    op TEXT NOT NULL DEFAULT 'write',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS launch_intents (
    intent_id TEXT PRIMARY KEY,
    request_id TEXT,
    payload_sha256 TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT 'default',
    dispatch_id TEXT NOT NULL,
    terminal_handle TEXT NOT NULL,
    lane_dir TEXT NOT NULL,
    worktree TEXT,
    backend TEXT,
    phase TEXT NOT NULL,
    outcome TEXT,
    owner_token TEXT NOT NULL,
    owner_pid INTEGER,
    owner_host TEXT,
    epoch INTEGER NOT NULL DEFAULT 1,
    receipt_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"#;

const MIGRATIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "gates",
        &[
            ("task_id", "TEXT"),
            ("message_id", "TEXT"),
            ("prev_status", "TEXT"),
            ("kind", "TEXT DEFAULT 'ask'"),
        ],
    ),
    ("runs", &[("objective", "TEXT")]),
    ("terminals", &[("backend_ref", "TEXT")]),
    (
        "dispatches",
        &[
            ("backend_ref", "TEXT"),
            ("head_sha", "TEXT"),
            ("monitor_pid", "INTEGER"),
            ("monitor_started_at", "REAL"),
            ("intent_id", "TEXT"),
            ("gate_closed_at", "REAL"),
        ],
    ),
    (
        "requests",
        &[
            ("payload_sha256", "TEXT"),
            ("intent_id", "TEXT"),
            ("claim_pid", "INTEGER"),
            ("claim_host", "TEXT"),
            ("caller_scope", "TEXT"),
            ("contacted_runtime", "INTEGER NOT NULL DEFAULT 0"),
            ("claimed_task_id", "TEXT"),
        ],
    ),
];

struct ConflictRecord {
    file: String,
    worker: String,
    other_worker: String,
    lines: [i64; 2],
    other_lines: [i64; 2],
}

impl ConflictRecord {
    fn to_json(&self) -> Value {
        json!({
            "kind": "overlapping_hunk",
            "file": self.file,
            "worker": self.worker,
            "otherWorker": self.other_worker,
            "lines": self.lines,
            "otherLines": self.other_lines,
        })
    }
}

struct TouchContext<'a> {
    cwd: &'a Path,
    home: &'a str,
    wt_real: Option<PathBuf>,
}

fn unix_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn random_id(prefix: &str) -> Result<String, String> {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

fn expand_tilde(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    if path == "~" {
        return home.to_string();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    path.to_string()
}

fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let abs = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(&last) = out.last() {
                    if last != ".." {
                        out.pop();
                        continue;
                    }
                }
                if !abs {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    if abs {
        if out.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", out.join("/"))
        }
    } else if out.is_empty() {
        ".".to_string()
    } else {
        out.join("/")
    }
}

impl<'a> TouchContext<'a> {
    fn joined(&self, p: &str) -> PathBuf {
        let expanded = expand_tilde(p, self.home);
        let ep = Path::new(&expanded);
        if ep.is_absolute() {
            ep.to_path_buf()
        } else {
            self.cwd.join(ep)
        }
    }

    fn rel(&self, p: &str) -> String {
        let joined = self.joined(p);
        let ap = fs::canonicalize(&joined)
            .unwrap_or_else(|_| path_guard::resolve_dir(&joined.to_string_lossy(), self.cwd));
        if let Some(ref wt) = self.wt_real {
            if ap == *wt {
                return ".".to_string();
            }
            if let Ok(stripped) = ap.strip_prefix(wt) {
                return posix_normpath(&stripped.to_string_lossy());
            }
        }
        posix_normpath(&ap.to_string_lossy())
    }

    fn read_file(&self, p: &str) -> Option<String> {
        let full = self.joined(p);
        let fh = File::open(full).ok()?;
        let mut buf = Vec::new();
        fh.take(MAX_READ_BYTES).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    fn locate(&self, p: &str, chunk: &str) -> Option<(i64, i64)> {
        if chunk.is_empty() {
            return None;
        }
        let text = self.read_file(p)?;
        let idx = text.find(chunk)?;
        let start = text[..idx].bytes().filter(|&b| b == b'\n').count() as i64 + 1;
        let newlines = chunk.bytes().filter(|&b| b == b'\n').count() as i64;
        Some((start, start + newlines))
    }
}

fn ensure_private_db_path(db_path: &Path) -> Result<(), String> {
    if db_path == Path::new(":memory:") {
        return Ok(());
    }
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| format!("cannot create state db dir: {e}"))?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create state db dir: {e}"))?;
            }
        }
    }
    if !db_path.exists() {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let _ = opts.open(db_path);
    }
    Ok(())
}

fn ensure_wal(conn: &Connection) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(BUSY_TIMEOUT_MS);
    let mut delay = Duration::from_millis(5);
    loop {
        let mode_res: Result<String, rusqlite::Error> =
            conn.query_row("PRAGMA journal_mode;", [], |row| row.get(0));
        match mode_res {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(_) => {
                let set_res: Result<String, rusqlite::Error> =
                    conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0));
                match set_res {
                    Ok(_) => return Ok(()),
                    Err(err) => {
                        let msg = err.to_string().to_ascii_lowercase();
                        if (!msg.contains("locked") && !msg.contains("busy"))
                            || Instant::now() >= deadline
                        {
                            return Err(format!("PRAGMA journal_mode=WAL failed: {err}"));
                        }
                    }
                }
            }
            Err(err) => {
                let msg = err.to_string().to_ascii_lowercase();
                if (!msg.contains("locked") && !msg.contains("busy")) || Instant::now() >= deadline
                {
                    return Err(format!("PRAGMA journal_mode check failed: {err}"));
                }
            }
        }
        thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

fn migrate_tables(conn: &Connection) -> Result<(), String> {
    for &(table, cols) in MIGRATIONS {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = conn
            .prepare(&pragma)
            .map_err(|e| format!("table_info({table}): {e}"))?;
        let have: BTreeSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| format!("table_info query({table}): {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        for &(col, decl) in cols {
            if !have.contains(col) {
                let sql = format!("ALTER TABLE {table} ADD COLUMN {col} {decl}");
                if let Err(err) = conn.execute(&sql, []) {
                    if !err
                        .to_string()
                        .to_ascii_lowercase()
                        .contains("duplicate column")
                    {
                        return Err(format!("migrate {table}.{col}: {err}"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn open_and_init_db(db_path: &Path) -> Result<Connection, String> {
    ensure_private_db_path(db_path)?;
    let conn = Connection::open(db_path).map_err(|e| format!("sqlite open failed: {e}"))?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
        .map_err(|e| format!("busy_timeout failed: {e}"))?;
    conn.execute_batch(&format!("PRAGMA busy_timeout = {BUSY_TIMEOUT_MS};"))
        .map_err(|e| format!("PRAGMA busy_timeout failed: {e}"))?;
    ensure_wal(&conn)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|e| format!("PRAGMA foreign_keys failed: {e}"))?;

    let stamped: i32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|e| format!("PRAGMA user_version failed: {e}"))?;
    if stamped > SCHEMA_VERSION {
        return Err(format!(
            "{} carries schema version {stamped}, newer than this open-fleet's {SCHEMA_VERSION}: refusing to read it with an older layout (upgrade open-fleet)",
            db_path.display()
        ));
    }
    if stamped == SCHEMA_VERSION {
        return Ok(conn);
    }

    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| format!("BEGIN IMMEDIATE failed: {e}"))?;
    let init_res = (|| -> Result<(), String> {
        let rechecked: i32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .map_err(|e| format!("PRAGMA user_version failed: {e}"))?;
        if rechecked > SCHEMA_VERSION {
            return Err(format!(
                "{} carries schema version {rechecked}, newer than this open-fleet's {SCHEMA_VERSION}",
                db_path.display()
            ));
        }
        if rechecked < SCHEMA_VERSION {
            conn.execute_batch(SCHEMA_DDL)
                .map_err(|e| format!("schema DDL failed: {e}"))?;
            migrate_tables(&conn)?;
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
                .map_err(|e| format!("set user_version failed: {e}"))?;
        }
        Ok(())
    })();
    match init_res {
        Ok(()) => {
            conn.execute_batch("COMMIT;")
                .map_err(|e| format!("schema COMMIT failed: {e}"))?;
            Ok(conn)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

fn patch_marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^(\+\+\+ |@@ -\d)").expect("regex"))
}

fn codex_file_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\*\*\* (Add|Update|Delete) File:\s*(.+)$").expect("regex"))
}

fn codex_move_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\*\*\* Move to:\s*(.+)$").expect("regex"))
}

fn unified_minus_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^--- (?:a/)?([^\t\r\n]+)").expect("regex"))
}

fn unified_plus_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\+\+\+ (?:b/)?([^\t\r\n]+)").expect("regex"))
}

fn unified_hunk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@").expect("regex"))
}

fn add_range(
    ranges: &mut BTreeMap<String, Vec<(i64, i64)>>,
    ctx: &TouchContext<'_>,
    path: &str,
    rng: Option<(i64, i64)>,
) {
    ranges
        .entry(ctx.rel(path))
        .or_default()
        .push(rng.unwrap_or(WHOLE_RANGE));
}

fn extract_patch_ranges(
    blob: &str,
    ctx: &TouchContext<'_>,
    ranges: &mut BTreeMap<String, Vec<(i64, i64)>>,
) {
    let mut cur: Option<String> = None;
    let mut mode: Option<String> = None;
    let mut old_lines: Vec<String> = Vec::new();
    let mut minus: Option<String> = None;

    let flush = |cur: &Option<String>,
                 mode: &Option<String>,
                 old_lines: &mut Vec<String>,
                 ranges: &mut BTreeMap<String, Vec<(i64, i64)>>| {
        if let Some(ref c) = cur {
            if mode.as_deref() == Some("update") && !old_lines.is_empty() {
                let chunk = old_lines.join("\n");
                add_range(ranges, ctx, c, ctx.locate(c, &chunk));
            }
        }
        old_lines.clear();
    };

    for ln in blob.lines() {
        if let Some(cap) = codex_file_re().captures(ln) {
            flush(&cur, &mode, &mut old_lines, ranges);
            let m = cap[1].to_ascii_lowercase();
            let target = cap[2].trim().to_string();
            if m != "update" {
                add_range(ranges, ctx, &target, None);
            }
            cur = Some(target);
            mode = Some(m);
            continue;
        }
        if let Some(cap) = codex_move_re().captures(ln) {
            add_range(ranges, ctx, cap[1].trim(), None);
            continue;
        }
        if ln.starts_with("*** ") {
            flush(&cur, &mode, &mut old_lines, ranges);
            continue;
        }
        if mode.as_deref() != Some("update") {
            if let Some(cap) = unified_minus_re().captures(ln) {
                minus = Some(cap[1].trim().to_string());
                continue;
            }
            if let Some(cap) = unified_plus_re().captures(ln) {
                let name = cap[1].trim();
                let resolved_cur = if name == "/dev/null" {
                    minus.clone()
                } else {
                    Some(name.to_string())
                };
                if name == "/dev/null" || minus.as_deref() == Some("/dev/null") {
                    if let Some(ref c) = resolved_cur {
                        add_range(ranges, ctx, c, None);
                    }
                }
                cur = resolved_cur;
                mode = Some("unified".to_string());
                continue;
            }
        }
        if mode.as_deref() == Some("unified") {
            if let Some(cap) = unified_hunk_re().captures(ln) {
                if let Some(ref c) = cur {
                    if c != "/dev/null" {
                        let a = cap[1].parse::<i64>().unwrap_or(1);
                        let b = cap
                            .get(2)
                            .and_then(|m| m.as_str().parse::<i64>().ok())
                            .unwrap_or(1);
                        let start = a.max(1);
                        let end = start + b.max(1) - 1;
                        add_range(ranges, ctx, c, Some((start, end)));
                    }
                }
            }
            continue;
        }
        if mode.as_deref() == Some("update") {
            if ln.starts_with("@@") {
                flush(&cur, &mode, &mut old_lines, ranges);
            } else if let Some(rest) = ln.strip_prefix(' ').or_else(|| ln.strip_prefix('-')) {
                old_lines.push(rest.to_string());
            } else if ln.is_empty() {
                old_lines.push(String::new());
            }
        }
    }
    flush(&cur, &mode, &mut old_lines, ranges);
}

fn extract_tool_input(doc: &Value, cfg: &HookConfig) -> Map<String, Value> {
    let Some(obj) = doc.as_object() else {
        return Map::new();
    };
    if let Some(ti) = obj.get("tool_input") {
        if let Some(map) = ti.as_object() {
            return map.clone();
        }
        if let Some(s) = ti.as_str() {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(s) {
                return map;
            }
            let mut map = Map::new();
            map.insert("patch".to_string(), Value::String(s.to_string()));
            return map;
        }
    }
    if cfg.jcode_tool_name.is_some() && !obj.contains_key("tool_name") {
        return obj.clone();
    }
    if let Some(Value::Object(map)) = obj.get("input") {
        return map.clone();
    }
    Map::new()
}

fn first_nonempty_str<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    for &k in keys {
        if let Some(s) = map.get(k).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn first_str<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    for &k in keys {
        if let Some(s) = map.get(k).and_then(Value::as_str) {
            return Some(s);
        }
    }
    None
}

fn collect_ranges(
    doc: &Value,
    ti: &Map<String, Value>,
    ctx: &TouchContext<'_>,
) -> BTreeMap<String, Vec<(i64, i64)>> {
    let mut ranges: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let top = first_nonempty_str(ti, TOP_PATH_KEYS).unwrap_or("");
    let old = first_str(ti, OLD_KEYS);
    if !top.is_empty() {
        if let Some(old_s) = old {
            add_range(&mut ranges, ctx, top, ctx.locate(top, old_s));
        }
        if let Some(ins) = ti.get("insert_line").and_then(Value::as_i64) {
            add_range(&mut ranges, ctx, top, Some((ins.max(1), ins + 1)));
        }
    }
    if let Some(edits) = ti.get("edits").and_then(Value::as_array) {
        for ed in edits {
            let Some(ed_map) = ed.as_object() else {
                continue;
            };
            let ep = first_nonempty_str(ed_map, EDIT_PATH_KEYS).unwrap_or(top);
            let eo = first_str(ed_map, OLD_KEYS);
            if !ep.is_empty() {
                let loc = eo.and_then(|s| ctx.locate(ep, s));
                add_range(&mut ranges, ctx, ep, loc);
            }
        }
    }
    let mut blobs: Vec<&str> = ti.values().filter_map(Value::as_str).collect();
    if let Some(patch_str) = doc.get("patch").and_then(Value::as_str) {
        blobs.push(patch_str);
    }
    for blob in blobs {
        if blob.contains("*** Begin Patch") || patch_marker_re().is_match(blob) {
            extract_patch_ranges(blob, ctx, &mut ranges);
        }
    }
    ranges
}

struct TouchInsert<'a> {
    run_id: &'a str,
    worker_id: &'a str,
    file_path: &'a str,
    start_line: i64,
    end_line: i64,
    op: &'a str,
}

fn insert_touch_and_check(
    conn: &Connection,
    touch: &TouchInsert<'_>,
) -> Result<Vec<ConflictRecord>, String> {
    let norm_path = posix_normpath(touch.file_path);
    let s_line = touch.start_line.max(1);
    let e_line = touch.end_line.max(s_line);
    let now = unix_timestamp();

    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| format!("BEGIN IMMEDIATE failed: {e}"))?;
    let tx_res = (|| -> Result<Vec<ConflictRecord>, String> {
        let mut overlapping = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT worker_id, start_line, end_line \
                     FROM file_touches \
                     WHERE run_id = ?1 AND file_path = ?2 AND worker_id != ?3",
                )
                .map_err(|e| format!("query file_touches failed: {e}"))?;
            let rows = stmt
                .query_map(params![touch.run_id, norm_path, touch.worker_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| format!("read file_touches failed: {e}"))?;
            for row in rows {
                let (other_worker, o_start, o_end) =
                    row.map_err(|e| format!("decode file_touches row failed: {e}"))?;
                if s_line.max(o_start) <= e_line.min(o_end) {
                    overlapping.push(ConflictRecord {
                        file: norm_path.clone(),
                        worker: touch.worker_id.to_string(),
                        other_worker,
                        lines: [s_line, e_line],
                        other_lines: [o_start, o_end],
                    });
                }
            }
        }
        conn.execute(
            "INSERT INTO file_touches(run_id, worker_id, file_path, start_line, end_line, op, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                touch.run_id,
                touch.worker_id,
                norm_path,
                s_line,
                e_line,
                touch.op,
                now
            ],
        )
        .map_err(|e| format!("insert file_touches failed: {e}"))?;
        Ok(overlapping)
    })();

    match tx_res {
        Ok(conflicts) => {
            conn.execute_batch("COMMIT;")
                .map_err(|e| format!("COMMIT file_touches failed: {e}"))?;
            Ok(conflicts)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

fn send_conflict_escalation(
    conn: &Connection,
    run_id: &str,
    worker_id: &str,
    conflicts: &[ConflictRecord],
) -> Result<(), String> {
    let msg_id = random_id("msg")?;
    let deliv_id = random_id("dlv")?;
    let now = unix_timestamp();
    let subject = format!("file-touch conflict on {}", conflicts[0].file);
    let conflict_vals: Vec<Value> = conflicts.iter().map(ConflictRecord::to_json).collect();
    let payload = serde_json::to_string(&conflict_vals)
        .map_err(|e| format!("serialize conflict payload: {e}"))?;
    let attrs_json = serde_json::to_string(&json!({ "fileTouchConflict": conflict_vals }))
        .map_err(|e| format!("serialize conflict attrs: {e}"))?;

    conn.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| format!("BEGIN IMMEDIATE escalation failed: {e}"))?;
    let tx_res = (|| -> Result<(), String> {
        conn.execute(
            "INSERT INTO messages(id, run_id, sender, recipient, msg_type, subject, outcome, payload, attrs_json, reply_to, created_at) \
             VALUES (?1, ?2, ?3, 'coordinator', 'escalation', ?4, NULL, ?5, ?6, NULL, ?7)",
            params![msg_id, run_id, worker_id, subject, payload, attrs_json, now],
        )
        .map_err(|e| format!("insert escalation message failed: {e}"))?;
        conn.execute(
            "INSERT INTO deliveries(delivery_id, message_id, recipient, run_id, acked, created_at) \
             VALUES (?1, ?2, 'coordinator', ?3, 0, ?4)",
            params![deliv_id, msg_id, run_id, now],
        )
        .map_err(|e| format!("insert escalation delivery failed: {e}"))?;
        Ok(())
    })();

    match tx_res {
        Ok(()) => {
            conn.execute_batch("COMMIT;")
                .map_err(|e| format!("COMMIT escalation failed: {e}"))?;
            Ok(())
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

fn record_touches_inner(
    parsed: &ParsedPayload,
    bound: Option<&Path>,
    cfg: &HookConfig,
) -> Result<(), String> {
    let Some(ref db_str) = cfg.state_db else {
        return Ok(());
    };
    if db_str.is_empty() {
        return Ok(());
    }

    let paths: Vec<&str> = if parsed.norm_tool == "Bash" {
        parsed
            .heredoc_targets
            .iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        let mut out = Vec::new();
        if !parsed.file.is_empty() {
            out.push(parsed.file.as_str());
        }
        for extra in &parsed.extra_files {
            if !extra.is_empty() {
                out.push(extra.as_str());
            }
        }
        out
    };
    if paths.is_empty() {
        return Ok(());
    }

    let wt_real = match bound {
        Some(b) => Some(fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf())),
        None => cfg
            .unit_worktree
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wt| fs::canonicalize(wt).unwrap_or_else(|_| PathBuf::from(wt))),
    };
    let ctx = TouchContext {
        cwd: &cfg.cwd,
        home: &cfg.home,
        wt_real,
    };

    let ti = extract_tool_input(&parsed.payload_json, cfg);
    let ranges = collect_ranges(&parsed.payload_json, &ti, &ctx);
    let op = parsed.norm_tool.to_ascii_lowercase();
    let conn = open_and_init_db(Path::new(db_str))?;

    let mut conflicts: Vec<ConflictRecord> = Vec::new();
    let mut seen: BTreeSet<(String, i64, i64)> = BTreeSet::new();
    for p in paths {
        let key = ctx.rel(p);
        let target_ranges: &[(i64, i64)] = ranges
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or(&[WHOLE_RANGE]);
        for &(start, end) in target_ranges {
            let s_line = start.max(1);
            let e_line = end.max(s_line);
            if !seen.insert((key.clone(), s_line, e_line)) {
                continue;
            }
            let touch = TouchInsert {
                run_id: &cfg.run_id,
                worker_id: &cfg.worker_id,
                file_path: &key,
                start_line: s_line,
                end_line: e_line,
                op: &op,
            };
            let found = insert_touch_and_check(&conn, &touch)?;
            conflicts.extend(found);
        }
    }

    if conflicts.is_empty() {
        return Ok(());
    }

    for c in &conflicts {
        eprintln!(
            "deny-hook: WARNING file-touch conflict: {} lines [{}, {}] overlaps {} lines [{}, {}] (escalated to the coordinator; the edit is not blocked)",
            c.file, c.lines[0], c.lines[1], c.other_worker, c.other_lines[0], c.other_lines[1]
        );
    }
    if let Err(err) = send_conflict_escalation(&conn, &cfg.run_id, &cfg.worker_id, &conflicts) {
        eprintln!("deny-hook: NOTE conflict escalation not sent: {err}");
    }
    Ok(())
}

/// Records allowed file-touch line ranges into the shared SQLite WAL state store and escalates
/// overlapping hunk conflicts to the coordinator without blocking the edit.
pub fn record_touches(parsed: &ParsedPayload, bound: Option<&Path>, cfg: &HookConfig) {
    if cfg.state_db.as_deref().is_none_or(str::is_empty) {
        return;
    }
    if let Err(err) = record_touches_inner(parsed, bound, cfg) {
        eprintln!("deny-hook: NOTE file touch not recorded: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ParsedPayload;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut rnd = [0u8; 6];
            getrandom::getrandom(&mut rnd).expect("rnd");
            let p = std::env::temp_dir().join(format!("of-tdb-{tag}-{}", hex::encode(rnd)));
            fs::create_dir_all(&p).expect("mkdir");
            Self(fs::canonicalize(&p).unwrap_or(p))
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_cfg(wt: &Path, db: &Path, worker_id: &str) -> HookConfig {
        let mut cfg = HookConfig::from_env();
        cfg.unit_worktree = Some(wt.to_string_lossy().into_owned());
        cfg.cwd = wt.to_path_buf();
        cfg.state_db = Some(db.to_string_lossy().into_owned());
        cfg.worker_id = worker_id.to_string();
        cfg.run_id = "run-test".to_string();
        cfg
    }

    fn make_parsed(norm_tool: &str, file: &str, payload_json: Value) -> ParsedPayload {
        ParsedPayload {
            raw_tool: norm_tool.to_string(),
            norm_tool: norm_tool.to_string(),
            raw_command: String::new(),
            judged: String::new(),
            parts: Vec::new(),
            subs: Vec::new(),
            target_paths: Vec::new(),
            file: file.to_string(),
            extra_files: Vec::new(),
            heredoc_targets: Vec::new(),
            unparseable_patch: false,
            strict_payload: false,
            c_records: Vec::new(),
            a_records: Vec::new(),
            guard_segs: Vec::new(),
            all_views: Vec::new(),
            body_texts: Vec::new(),
            w_records: Vec::new(),
            fed_sub: false,
            fed_interp: Vec::new(),
            fed_blind: false,
            brace_refusal: None,
            unreceipted_egress: false,
            rline: String::new(),
            ro_write_kind: None,
            payload_json,
        }
    }

    #[test]
    fn overlapping_edits_record_and_escalate_while_disjoint_does_not() {
        let tmp = TempDir::new("conflict");
        let db = tmp.path().join("state/runtime.db");
        let wt_a = tmp.path().join("wt-a");
        let wt_b = tmp.path().join("wt-b");
        let content = "line1\nline2\nline3\nline4\nline5\nline6\n";
        for wt in [&wt_a, &wt_b] {
            fs::create_dir_all(wt.join("src")).expect("src");
            fs::write(wt.join("src/app.py"), content).expect("app");
        }

        let file_a = wt_a.join("src/app.py").to_string_lossy().into_owned();
        let file_b = wt_b.join("src/app.py").to_string_lossy().into_owned();

        let p_a = make_parsed(
            "Edit",
            &file_a,
            json!({"tool_name": "Edit", "tool_input": {"file_path": file_a, "old_string": "line2\nline3", "new_string": "X"}}),
        );
        record_touches(&p_a, Some(&wt_a), &make_cfg(&wt_a, &db, "w-a"));

        let p_b_disjoint = make_parsed(
            "Edit",
            &file_b,
            json!({"tool_name": "Edit", "tool_input": {"file_path": file_b, "old_string": "line5\nline6", "new_string": "Y"}}),
        );
        record_touches(&p_b_disjoint, Some(&wt_b), &make_cfg(&wt_b, &db, "w-b"));

        let conn = Connection::open(&db).expect("open db");
        let esc_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE msg_type = 'escalation'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(esc_before, 0);

        let p_b_overlap = make_parsed(
            "Edit",
            &file_b,
            json!({"tool_name": "Edit", "tool_input": {"file_path": file_b, "old_string": "line3\nline4", "new_string": "Z"}}),
        );
        record_touches(&p_b_overlap, Some(&wt_b), &make_cfg(&wt_b, &db, "w-b"));

        let user_ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .expect("user_version");
        assert_eq!(user_ver, 2);

        let mut stmt = conn
            .prepare(
                "SELECT worker_id, file_path, start_line, end_line FROM file_touches ORDER BY id",
            )
            .expect("prep");
        let rows: Vec<(String, String, i64, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("q")
            .map(|r| r.expect("row"))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("w-a".to_string(), "src/app.py".to_string(), 2, 3),
                ("w-b".to_string(), "src/app.py".to_string(), 5, 6),
                ("w-b".to_string(), "src/app.py".to_string(), 3, 4),
            ]
        );

        let (recip, attrs_str): (String, String) = conn
            .query_row(
                "SELECT recipient, attrs_json FROM messages WHERE msg_type = 'escalation'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("esc");
        assert_eq!(recip, "coordinator");
        let attrs: Value = serde_json::from_str(&attrs_str).expect("json");
        assert_eq!(attrs["fileTouchConflict"][0]["otherWorker"], "w-a");
        assert_eq!(attrs["fileTouchConflict"][0]["file"], "src/app.py");

        let dlv_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deliveries WHERE recipient = 'coordinator' AND acked = 0",
                [],
                |r| r.get(0),
            )
            .expect("dlv");
        assert_eq!(dlv_count, 1);
    }

    #[test]
    fn patch_hunks_and_codex_updates_extract_exact_ranges() {
        let tmp = TempDir::new("patch");
        let db = tmp.path().join("state.db");
        let wt = tmp.path().join("wt");
        fs::create_dir_all(wt.join("src")).expect("src");
        fs::write(
            wt.join("src/app.py"),
            "line1\nline2\nline3\nline4\nline5\nline6\n",
        )
        .expect("app");

        let unified =
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -4,2 +4,2 @@\n-line4\n-line5\n+L4\n+L5\n";
        let p1 = make_parsed(
            "Edit",
            "src/app.py",
            json!({"tool_name": "patch", "tool_input": {"path": "src/app.py", "diff": unified}}),
        );
        record_touches(&p1, Some(&wt), &make_cfg(&wt, &db, "w-a"));

        let codex = "*** Begin Patch\n*** Update File: src/app.py\n@@\n line2\n-line3\n+L3\n*** End Patch\n";
        let p2 = make_parsed(
            "Edit",
            "src/app.py",
            json!({"tool_name": "apply_patch", "tool_input": {"command": codex}}),
        );
        record_touches(&p2, Some(&wt), &make_cfg(&wt, &db, "w-a"));

        let conn = Connection::open(&db).expect("db");
        let mut stmt = conn
            .prepare("SELECT file_path, start_line, end_line FROM file_touches ORDER BY id")
            .expect("prep");
        let rows: Vec<(String, i64, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("q")
            .map(|r| r.expect("row"))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("src/app.py".to_string(), 4, 5),
                ("src/app.py".to_string(), 2, 3),
            ]
        );
    }
}
