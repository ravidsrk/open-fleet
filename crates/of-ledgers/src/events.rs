//! Native Rust port of `runtime/scripts/events.py`:
//! append-only lifecycle event record, tamper-evident hash chain, strictly read-only
//! store/transcript/stream ingesters, and deterministic WIP-curve derivation (#603, #763).

use crate::egress::{sha256_hex, sha256_hex_bytes, valid_ts};
use chrono::{DateTime, Utc};
use of_common::decisions::{redact_secrets, secret_hits as common_secret_hits};
use of_common::wip_rows::{wip_rows, WIP_ROW_KEYS};
use regex::Regex;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Map, Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

pub const EXIT_OK: i32 = 0;
pub const EXIT_INCOMPLETE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FAIL_CLOSED: i32 = 3;

pub const DEFAULT_LOG: &str = ".orca/events.jsonl";
pub const PRIMARY_LOG_ENV: &str = "OPEN_FLEET_EVENTS_LOG";
pub const LOG_ENV: &str = "ORCA_EVENTS_LOG";
pub const RECORD_VERSION: i64 = 1;
pub const REPORT_SCHEMA: &str = "open-fleet.events-report/1";
pub const MAX_TEXT_BYTES: usize = 512;
pub const UNAVAILABLE: &str = "unavailable";

pub const FIELDS: &[&str] = &[
    "v",
    "event_id",
    "kind",
    "run",
    "task",
    "dispatch",
    "epoch",
    "producer",
    "observed_at",
    "clock",
    "basis",
    "source",
    "data",
];

pub const BASES: &[&str] = &["occurred", "observed", "recovered"];

pub const TOKEN_FIELDS: &[&str] = &[
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
];

pub const USAGE_FIELDS: &[&str] = &[
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "cost_usd",
];

pub const KINDS: &[&str] = &[
    "coordinator.resume",
    "dispatch.died",
    "dispatch.launched",
    "model.usage",
    "review.started",
    "review.verdict",
    "review.voided",
    "run.start",
    "task.done",
    "unit.closed",
    "unit.parked",
    "unit.suspect",
    "verify.verdict",
    "wave.close",
    "wave.open",
];

const DECLARES_EPOCH: &[&str] = &["run.start", "coordinator.resume"];
const VERDICTS: &[&str] = &["approve", "changes"];
const CLOSED_OR_PARKED: &[&str] = &["verified-closed", "closed-unverified", "parked"];
const LEFT_DISPATCHED: &[&str] = &["verified-closed", "closed-unverified", "parked", "verified"];
const ROW_METRICS: &[&str] = &[
    "throughput",
    "latency_median",
    "latency_max",
    "rework",
    "freshness",
];
const TERMINAL_DISPATCH_STATES: &[&str] =
    &["completed", "died", "stopped", "abandoned", "released"];

const ID_PATTERN_STR: &str = r"[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,199}";

fn id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,199}\z").expect("regex"))
}

fn sha_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\z").expect("regex"))
}

fn hex64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[0-9a-f]{64}\z").expect("regex"))
}

fn money_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[0-9]+(?:\.[0-9]+)?\z").expect("regex"))
}

fn url_credential_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s@:]+:[^/\s@]+@").expect("regex"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventsError {
    Usage(String),
    FailClosed(String),
}

impl fmt::Display for EventsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) | Self::FailClosed(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for EventsError {}

pub fn log_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        if !p.as_os_str().is_empty() {
            return p.to_path_buf();
        }
    }
    for var in [PRIMARY_LOG_ENV, LOG_ENV] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                return PathBuf::from(val);
            }
        }
    }
    PathBuf::from(DEFAULT_LOG)
}

pub fn secret_hits(text: &str) -> Vec<&'static str> {
    let mut hits: BTreeSet<&'static str> = common_secret_hits(text).into_iter().collect();
    if url_credential_re().is_match(text) {
        hits.insert("url-credential");
    }
    hits.into_iter().collect()
}

pub fn redact_str(text: &str) -> String {
    let stage1 = redact_secrets(text);
    url_credential_re()
        .replace_all(&stage1, "[REDACTED:url-credential]@")
        .into_owned()
}

pub fn redact(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(redact_str(&k), redact(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        Value::String(s) => Value::String(redact_str(&s)),
        other => other,
    }
}

// ---------------------------------------------------------------------------- Python-exact formatting

fn py_repr_str(s: &str) -> String {
    let use_double = s.contains('\'') && !s.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(quote);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn py_repr_opt_str(opt: Option<&str>) -> String {
    match opt {
        Some(s) => py_repr_str(s),
        None => "None".to_string(),
    }
}

fn py_list_str(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn py_list_str_refs(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn py_list_i64(items: &[i64]) -> String {
    let inner: Vec<String> = items.iter().map(ToString::to_string).collect();
    format!("[{}]", inner.join(", "))
}

fn py_repr_value(val: &Value) -> String {
    match val {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_repr_str(s),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(py_repr_value).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr_str(k), py_repr_value(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn json_escape_ascii(s: &str, out: &mut String) {
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
}

fn write_canonical_json(val: &Value, out: &mut String) {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => json_escape_ascii(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (idx, k) in keys.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                json_escape_ascii(k, out);
                out.push(':');
                write_canonical_json(&map[k], out);
            }
            out.push('}');
        }
    }
}

/// Exact byte-for-byte match for Python `json.dumps(v, sort_keys=True, separators=(",", ":"))`.
pub fn py_canonical_json(val: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(val, &mut out);
    out
}

fn write_pretty_json(val: &Value, depth: usize, out: &mut String) {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => json_escape_ascii(s, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            let child_indent = "  ".repeat(depth + 1);
            for (idx, item) in items.iter().enumerate() {
                out.push_str(&child_indent);
                write_pretty_json(item, depth + 1, out);
                if idx + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(depth));
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            let child_indent = "  ".repeat(depth + 1);
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let count = keys.len();
            for (idx, k) in keys.into_iter().enumerate() {
                out.push_str(&child_indent);
                json_escape_ascii(k, out);
                out.push_str(": ");
                write_pretty_json(&map[k], depth + 1, out);
                if idx + 1 < count {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(depth));
            out.push('}');
        }
    }
}

/// Exact byte-for-byte match for Python `json.dumps(v, indent=2, sort_keys=True)`.
pub fn py_pretty_json(val: &Value) -> String {
    let mut out = String::new();
    write_pretty_json(val, 0, &mut out);
    out
}

/// Replaces bare JSON `NaN`, `Infinity`, and `-Infinity` tokens (outside string literals)
/// with `null` so `serde_json` matches Python `json.loads` on streams carrying non-finite floats.
fn sanitize_json_nonfinite(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while i < len {
        let b = bytes[i];
        if in_string {
            let ch = raw[i..].chars().next().expect("char");
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            i += ch.len_utf8();
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        let rest = &raw[i..];
        let matched = if rest.starts_with("-Infinity") {
            Some(9usize)
        } else if rest.starts_with("Infinity") {
            Some(8usize)
        } else if rest.starts_with("NaN") {
            Some(3usize)
        } else {
            None
        };
        if let Some(tok_len) = matched {
            let prev_ok = i == 0
                || matches!(
                    bytes[i - 1],
                    b':' | b',' | b'[' | b' ' | b'\t' | b'\r' | b'\n'
                );
            let next_ok = i + tok_len == len
                || matches!(
                    bytes[i + tok_len],
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n'
                );
            if prev_ok && next_ok {
                out.push_str("null");
                i += tok_len;
                continue;
            }
        }
        let ch = raw[i..].chars().next().expect("char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn parse_json_lenient_nonfinite(raw: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        return Some(v);
    }
    let sanitized = sanitize_json_nonfinite(raw);
    serde_json::from_str::<Value>(&sanitized).ok()
}

// ---------------------------------------------------------------------------- exact math

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Exact reduced rational matching Python `fractions.Fraction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frac {
    pub num: i128,
    pub den: i128,
}

impl Frac {
    pub fn new(num: i128, den: i128) -> Self {
        assert!(den != 0, "zero denominator");
        let (n, d) = if den < 0 { (-num, -den) } else { (num, den) };
        if n == 0 {
            return Self { num: 0, den: 1 };
        }
        let g = gcd_u128(n.unsigned_abs(), d.unsigned_abs()) as i128;
        Self {
            num: n / g,
            den: d / g,
        }
    }

    pub fn from_int(n: i128) -> Self {
        Self { num: n, den: 1 }
    }

    pub fn div_int(self, divisor: i128) -> Self {
        Self::new(self.num, self.den * divisor)
    }

    pub fn div_frac(self, other: Self) -> Self {
        Self::new(self.num * other.den, self.den * other.num)
    }
}

impl std::ops::Add for Frac {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let g = gcd_u128(self.den.unsigned_abs(), other.den.unsigned_abs()) as i128;
        let num = self.num * (other.den / g) + other.num * (self.den / g);
        let den = (self.den / g) * other.den;
        Self::new(num, den)
    }
}

impl Ord for Frac {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.num * other.den).cmp(&(other.num * self.den))
    }
}

impl PartialOrd for Frac {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Frac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.den == 1 {
            write!(f, "{}", self.num)
        } else {
            write!(f, "{}/{}", self.num, self.den)
        }
    }
}

/// Exact `ROUND_HALF_EVEN` decimal formatting matching Python `_decimal(frac, places=2)`.
pub fn format_decimal_half_even(frac: Frac, places: u32) -> String {
    let neg = frac.num < 0;
    let n = frac.num.unsigned_abs();
    let d = frac.den.unsigned_abs();
    let scale = 10u128.pow(places);

    let whole = n / d;
    let rem = n % d;
    let scaled_rem = rem * scale;
    let frac_q = scaled_rem / d;
    let r = scaled_rem % d;
    let total_before = whole * scale + frac_q;
    let twice_r = r * 2;
    let inc = match twice_r.cmp(&d) {
        Ordering::Greater => 1u128,
        Ordering::Less => 0u128,
        Ordering::Equal => {
            if total_before % 2 == 1 {
                1u128
            } else {
                0u128
            }
        }
    };
    let rounded = total_before + inc;
    let sign = if neg { "-" } else { "" };
    if places == 0 {
        format!("{sign}{rounded}")
    } else {
        let int_part = rounded / scale;
        let dec_part = rounded % scale;
        format!(
            "{sign}{int_part}.{dec_part:0width$}",
            width = places as usize
        )
    }
}

fn minutes(seconds: Frac) -> String {
    format!("{}m", format_decimal_half_even(seconds.div_int(60), 2))
}

fn median(values: &[Frac]) -> Frac {
    let mut ordered = values.to_vec();
    ordered.sort();
    let mid = ordered.len() / 2;
    if ordered.len() % 2 == 1 {
        ordered[mid]
    } else {
        (ordered[mid - 1] + ordered[mid]).div_int(2)
    }
}

/// Exact arbitrary-precision non-negative decimal preserving scale like Python `Decimal`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MoneyDecimal {
    /// Big-endian base-10 digits (0..=9), no leading zeros except single [0].
    digits: Vec<u8>,
    scale: usize,
}

impl MoneyDecimal {
    fn zero() -> Self {
        Self {
            digits: vec![0],
            scale: 0,
        }
    }

    fn parse(s: &str) -> Self {
        let (int_part, frac_part) = match s.split_once('.') {
            Some((a, b)) => (a, b),
            None => (s, ""),
        };
        let scale = frac_part.len();
        let mut digits = Vec::with_capacity(int_part.len() + frac_part.len());
        for b in int_part.bytes().chain(frac_part.bytes()) {
            digits.push(b - b'0');
        }
        let mut d = Self { digits, scale };
        d.trim_leading_zeros();
        d
    }

    fn trim_leading_zeros(&mut self) {
        let first_nz = self.digits.iter().position(|&d| d != 0);
        match first_nz {
            Some(pos) if pos > 0 => {
                self.digits.drain(0..pos);
            }
            None => {
                self.digits.clear();
                self.digits.push(0);
            }
            _ => {}
        }
    }

    fn scaled_digits(&self, target_scale: usize) -> Vec<u8> {
        let extra = target_scale - self.scale;
        if self.digits.len() == 1 && self.digits[0] == 0 {
            return vec![0];
        }
        let mut out = Vec::with_capacity(self.digits.len() + extra);
        out.extend_from_slice(&self.digits);
        out.resize(out.len() + extra, 0);
        out
    }

    fn add_assign(&mut self, other: &Self) {
        let target_scale = self.scale.max(other.scale);
        let a = self.scaled_digits(target_scale);
        let b = other.scaled_digits(target_scale);
        let max_len = a.len().max(b.len());
        let mut rev = Vec::with_capacity(max_len + 1);
        let mut carry = 0u8;
        for idx in 0..max_len {
            let da = if idx < a.len() {
                a[a.len() - 1 - idx]
            } else {
                0
            };
            let db = if idx < b.len() {
                b[b.len() - 1 - idx]
            } else {
                0
            };
            let sum = da + db + carry;
            rev.push(sum % 10);
            carry = sum / 10;
        }
        if carry > 0 {
            rev.push(carry);
        }
        rev.reverse();
        self.digits = rev;
        self.scale = target_scale;
        self.trim_leading_zeros();
    }

    fn format_fixed(&self) -> String {
        if self.scale == 0 {
            return self.digits.iter().map(|&d| (b'0' + d) as char).collect();
        }
        let need = self.scale + 1;
        let mut all = Vec::with_capacity(self.digits.len().max(need));
        if self.digits.len() < need {
            all.resize(need - self.digits.len(), 0);
        }
        all.extend_from_slice(&self.digits);
        let split = all.len() - self.scale;
        let mut out = String::with_capacity(all.len() + 1);
        for &d in &all[..split] {
            out.push((b'0' + d) as char);
        }
        out.push('.');
        for &d in &all[split..] {
            out.push((b'0' + d) as char);
        }
        out
    }
}

fn parse_money_json(val: Option<&Value>) -> Option<String> {
    let Value::Number(n) = val? else {
        return None;
    };
    if let Some(u) = n.as_u64() {
        return Some(u.to_string());
    }
    if let Some(i) = n.as_i64() {
        return if i < 0 { None } else { Some(i.to_string()) };
    }
    let f = n.as_f64()?;
    if !f.is_finite() || f < 0.0 {
        return None;
    }
    if f == 0.0 && f.is_sign_negative() {
        return None;
    }
    let s = format!("{f}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') && f < 1e16 {
        Some(format!("{s}.0"))
    } else {
        Some(s)
    }
}

// ---------------------------------------------------------------------------- schema

#[derive(Debug, Clone, Copy)]
enum FieldType {
    Id,
    Text,
    Pos,
    Count,
    Sha,
    Verdict,
    Money,
    Ids,
}

struct KindSpec {
    task_req: bool,
    dispatch_req: bool,
    data: &'static [(&'static str, FieldType, bool)],
}

fn kind_spec(kind: &str) -> Option<KindSpec> {
    const R: bool = true;
    const O: bool = false;
    match kind {
        "run.start" => Some(KindSpec {
            task_req: false,
            dispatch_req: false,
            data: &[("coordinator", FieldType::Id, R)],
        }),
        "coordinator.resume" => Some(KindSpec {
            task_req: false,
            dispatch_req: false,
            data: &[("coordinator", FieldType::Id, R)],
        }),
        "wave.open" => Some(KindSpec {
            task_req: false,
            dispatch_req: false,
            data: &[
                ("builders", FieldType::Count, R),
                ("reviewers", FieldType::Count, R),
                ("tasks", FieldType::Ids, R),
                ("wave", FieldType::Pos, R),
            ],
        }),
        "wave.close" => Some(KindSpec {
            task_req: false,
            dispatch_req: false,
            data: &[("wave", FieldType::Pos, R)],
        }),
        "dispatch.launched" => Some(KindSpec {
            task_req: true,
            dispatch_req: true,
            data: &[("agent", FieldType::Id, O)],
        }),
        "dispatch.died" => Some(KindSpec {
            task_req: true,
            dispatch_req: true,
            data: &[],
        }),
        "task.done" => Some(KindSpec {
            task_req: true,
            dispatch_req: true,
            data: &[("head_sha", FieldType::Sha, O)],
        }),
        "review.started" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[("head_sha", FieldType::Sha, R)],
        }),
        "review.verdict" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[
                ("reviewed_sha", FieldType::Sha, R),
                ("reviewed_wtree", FieldType::Sha, O),
                ("verdict", FieldType::Verdict, R),
            ],
        }),
        "review.voided" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[
                ("head_sha", FieldType::Sha, R),
                ("reviewed_sha", FieldType::Sha, R),
            ],
        }),
        "verify.verdict" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[
                ("exit", FieldType::Count, R),
                ("head_sha", FieldType::Sha, O),
            ],
        }),
        "unit.closed" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[
                ("head_sha", FieldType::Sha, R),
                ("head_wtree", FieldType::Sha, O),
            ],
        }),
        "unit.parked" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[
                ("head_sha", FieldType::Sha, O),
                ("park_class", FieldType::Id, R),
            ],
        }),
        "unit.suspect" => Some(KindSpec {
            task_req: true,
            dispatch_req: false,
            data: &[],
        }),
        "model.usage" => Some(KindSpec {
            task_req: false,
            dispatch_req: false,
            data: &[
                ("cache_creation_input_tokens", FieldType::Count, O),
                ("cache_read_input_tokens", FieldType::Count, O),
                ("cost_usd", FieldType::Money, O),
                ("input_tokens", FieldType::Count, O),
                ("model", FieldType::Id, O),
                ("output_tokens", FieldType::Count, O),
                ("provenance", FieldType::Text, R),
            ],
        }),
        _ => None,
    }
}

fn check_text(
    value: Option<&Value>,
    name: &str,
    check_id: bool,
    limit: usize,
    strict: bool,
) -> Result<String, String> {
    let Some(Value::String(s)) = value else {
        return Err(format!("{name} must be a non-empty string"));
    };
    if s.trim().is_empty() {
        return Err(format!("{name} must be a non-empty string"));
    }
    if s.len() > limit {
        return Err(format!("{name} exceeds {limit} bytes"));
    }
    if s.chars().any(|c| (c as u32) < 32 || (c as u32) == 127) {
        return Err(format!(
            "{name} may not carry a control character (one event, one line)"
        ));
    }
    if strict {
        let hits = secret_hits(s);
        if !hits.is_empty() {
            return Err(format!(
                "{name} carries a credential shape ({}); the record is permanent, so the event is refused",
                hits.join(", ")
            ));
        }
    }
    if check_id && !id_re().is_match(s) {
        return Err(format!(
            "{name} {} is not an identifier ({ID_PATTERN_STR})",
            py_repr_str(s)
        ));
    }
    Ok(s.clone())
}

fn check_int(value: Option<&Value>, name: &str, low: i64) -> Result<i64, String> {
    let Some(Value::Number(n)) = value else {
        return Err(format!("{name} must be an integer >= {low}"));
    };
    let Some(i) = n.as_i64() else {
        return Err(format!("{name} must be an integer >= {low}"));
    };
    if i < low {
        return Err(format!("{name} must be an integer >= {low}"));
    }
    Ok(i)
}

fn check_typed(
    kind_type: FieldType,
    value: &Value,
    name: &str,
    strict: bool,
) -> Result<Value, String> {
    match kind_type {
        FieldType::Id => Ok(Value::String(check_text(
            Some(value),
            name,
            true,
            MAX_TEXT_BYTES,
            strict,
        )?)),
        FieldType::Text => Ok(Value::String(check_text(
            Some(value),
            name,
            false,
            256,
            strict,
        )?)),
        FieldType::Pos => Ok(Value::Number(Number::from(check_int(
            Some(value),
            name,
            1,
        )?))),
        FieldType::Count => Ok(Value::Number(Number::from(check_int(
            Some(value),
            name,
            0,
        )?))),
        FieldType::Sha => {
            let Some(Value::String(s)) = Some(value) else {
                return Err(format!("{name} must be a full lowercase commit/tree id"));
            };
            if !sha_re().is_match(s) {
                return Err(format!("{name} must be a full lowercase commit/tree id"));
            }
            Ok(Value::String(s.clone()))
        }
        FieldType::Verdict => {
            if let Value::String(s) = value {
                if VERDICTS.contains(&s.as_str()) {
                    return Ok(Value::String(s.clone()));
                }
            }
            Err(format!(
                "{name} must be one of {}",
                py_list_str_refs(VERDICTS)
            ))
        }
        FieldType::Money => {
            let Value::String(s) = value else {
                return Err(format!(
                    "{name} must be a non-negative decimal string like '0.42'"
                ));
            };
            if !money_re().is_match(s) {
                return Err(format!(
                    "{name} must be a non-negative decimal string like '0.42'"
                ));
            }
            Ok(Value::String(s.clone()))
        }
        FieldType::Ids => {
            let Value::Array(arr) = value else {
                return Err(format!("{name} must be a non-empty list of ids"));
            };
            if arr.is_empty() {
                return Err(format!("{name} must be a non-empty list of ids"));
            }
            let mut values = Vec::with_capacity(arr.len());
            let mut seen = HashSet::with_capacity(arr.len());
            for item in arr {
                let s = check_text(Some(item), name, true, MAX_TEXT_BYTES, strict)?;
                if !seen.insert(s.clone()) {
                    return Err(format!("{name} names an id twice"));
                }
                values.push(s);
            }
            values.sort();
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
    }
}

pub fn normalize(event: &Value, strict: bool) -> Result<Map<String, Value>, String> {
    let Value::Object(map) = event else {
        return Err("an event is a JSON object".to_string());
    };
    let mut unknown: Vec<String> = map
        .keys()
        .filter(|k| !FIELDS.contains(&k.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        return Err(format!("unknown field(s) {}", py_list_str(&unknown)));
    }
    if map.get("v").and_then(Value::as_i64) != Some(RECORD_VERSION) {
        return Err(format!("v must be {RECORD_VERSION}"));
    }
    let kind_val = map.get("kind");
    let kind = match kind_val {
        Some(Value::String(k)) if kind_spec(k).is_some() => k.as_str(),
        other => {
            let shown = other
                .map(py_repr_value)
                .unwrap_or_else(|| "None".to_string());
            return Err(format!(
                "kind {shown} is not one of {}",
                py_list_str_refs(KINDS)
            ));
        }
    };
    let spec = kind_spec(kind).expect("checked kind");
    let mut out = Map::new();
    out.insert("v".to_string(), Value::Number(Number::from(RECORD_VERSION)));
    out.insert("kind".to_string(), Value::String(kind.to_string()));
    out.insert(
        "event_id".to_string(),
        Value::String(check_text(
            map.get("event_id"),
            "event_id",
            true,
            MAX_TEXT_BYTES,
            strict,
        )?),
    );
    out.insert(
        "run".to_string(),
        Value::String(check_text(
            map.get("run"),
            "run",
            true,
            MAX_TEXT_BYTES,
            strict,
        )?),
    );
    for (key, required) in [("task", spec.task_req), ("dispatch", spec.dispatch_req)] {
        match map.get(key) {
            None | Some(Value::Null) => {
                if required {
                    return Err(format!("{kind} binds a {key}"));
                }
                out.insert(key.to_string(), Value::Null);
            }
            Some(v) => {
                out.insert(
                    key.to_string(),
                    Value::String(check_text(Some(v), key, true, MAX_TEXT_BYTES, strict)?),
                );
            }
        }
    }
    out.insert(
        "epoch".to_string(),
        Value::Number(Number::from(check_int(map.get("epoch"), "epoch", 1)?)),
    );
    out.insert(
        "producer".to_string(),
        Value::String(check_text(
            map.get("producer"),
            "producer",
            true,
            MAX_TEXT_BYTES,
            strict,
        )?),
    );
    out.insert(
        "clock".to_string(),
        Value::String(check_text(
            map.get("clock"),
            "clock",
            true,
            MAX_TEXT_BYTES,
            strict,
        )?),
    );
    let basis = match map.get("basis") {
        Some(Value::String(b)) if BASES.contains(&b.as_str()) => b.clone(),
        _ => {
            return Err(format!("basis must be one of {}", py_list_str_refs(BASES)));
        }
    };
    out.insert("basis".to_string(), Value::String(basis));
    let observed_at = match map.get("observed_at") {
        Some(Value::String(s)) => {
            valid_ts(s)?;
            s.clone()
        }
        other => {
            let shown = other
                .map(py_repr_value)
                .unwrap_or_else(|| "None".to_string());
            return Err(format!(
                "ts must be ISO-8601 like 2026-01-02T03:04:05Z, got {shown}"
            ));
        }
    };
    out.insert("observed_at".to_string(), Value::String(observed_at));
    let Some(Value::Object(source)) = map.get("source") else {
        return Err("source must be {ref, sha256}".to_string());
    };
    if source.len() != 2 || !source.contains_key("ref") || !source.contains_key("sha256") {
        return Err("source must be {ref, sha256}".to_string());
    }
    let digest = match source.get("sha256") {
        Some(Value::Null) => Value::Null,
        Some(Value::String(s)) if hex64_re().is_match(s) => Value::String(s.clone()),
        _ => {
            return Err("source.sha256 must be 64 lowercase hex characters or null".to_string());
        }
    };
    let source_ref = check_text(
        source.get("ref"),
        "source.ref",
        false,
        MAX_TEXT_BYTES,
        strict,
    )?;
    let mut source_out = Map::new();
    source_out.insert("ref".to_string(), Value::String(source_ref));
    source_out.insert("sha256".to_string(), digest);
    out.insert("source".to_string(), Value::Object(source_out));

    let Some(Value::Object(data)) = map.get("data") else {
        return Err("data must be an object".to_string());
    };
    let allowed_data: HashSet<&str> = spec.data.iter().map(|(k, _, _)| *k).collect();
    let mut extra: Vec<String> = data
        .keys()
        .filter(|k| !allowed_data.contains(k.as_str()))
        .cloned()
        .collect();
    if !extra.is_empty() {
        extra.sort();
        return Err(format!(
            "{kind} data carries unknown key(s) {}",
            py_list_str(&extra)
        ));
    }
    let mut data_out = Map::new();
    for &(key, kind_type, required) in spec.data {
        match data.get(key) {
            None | Some(Value::Null) => {
                if required {
                    return Err(format!("{kind} data requires {key}"));
                }
                data_out.insert(key.to_string(), Value::Null);
            }
            Some(v) => {
                let checked = check_typed(kind_type, v, &format!("data.{key}"), strict)?;
                data_out.insert(key.to_string(), checked);
            }
        }
    }
    out.insert("data".to_string(), Value::Object(data_out));
    Ok(out)
}

pub fn identity(event: &Map<String, Value>) -> Result<String, String> {
    let mut said = Map::new();
    for &k in FIELDS {
        if k == "epoch" || k == "observed_at" || k == "basis" {
            continue;
        }
        said.insert(k.to_string(), event.get(k).cloned().unwrap_or(Value::Null));
    }
    let basis_occurred = event.get("basis").and_then(Value::as_str) == Some("occurred");
    let occurred_at = if basis_occurred {
        event.get("observed_at").cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    said.insert("occurred_at".to_string(), occurred_at);

    let Some(Value::Object(src)) = said.get("source") else {
        return Err("missing source object".to_string());
    };
    let Some(sha_val) = src.get("sha256") else {
        return Err("missing source.sha256".to_string());
    };
    if !sha_val.is_null() {
        let mut norm_src = Map::new();
        norm_src.insert("ref".to_string(), Value::Null);
        norm_src.insert("sha256".to_string(), sha_val.clone());
        said.insert("source".to_string(), Value::Object(norm_src));
    }
    Ok(py_canonical_json(&Value::Object(said)))
}

pub fn bound_id(base: &str, head: Option<&str>) -> String {
    let tail = match head {
        Some(h) if !h.is_empty() => h,
        _ => "no-head",
    };
    format!("{base}@{tail}")
}

pub fn content_id(event: &Map<String, Value>) -> String {
    let mut subset = Map::new();
    for &k in FIELDS {
        if k == "epoch" || k == "event_id" {
            continue;
        }
        subset.insert(k.to_string(), event.get(k).cloned().unwrap_or(Value::Null));
    }
    format!(
        "content:{}",
        sha256_hex(&py_canonical_json(&Value::Object(subset)))
    )
}

fn is_py_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_i64() == Some(0) || n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

pub struct BuildEventParams<'a> {
    pub kind: &'a str,
    pub run: &'a str,
    pub epoch: i64,
    pub producer: &'a str,
    pub clock: &'a str,
    pub observed_at: &'a str,
    pub basis: &'a str,
    pub source_ref: &'a str,
    pub source_sha256: Option<&'a str>,
    pub task: Option<&'a str>,
    pub dispatch: Option<&'a str>,
    pub data: Option<Value>,
    pub event_id: Option<&'a str>,
}

pub fn build_event(params: &BuildEventParams<'_>) -> Result<Map<String, Value>, String> {
    let data_val = match &params.data {
        Some(v) if !is_py_falsy(v) => v.clone(),
        _ => Value::Object(Map::new()),
    };
    let eid_initial = match params.event_id {
        Some(s) if !s.is_empty() => s,
        _ => "x",
    };
    let mut raw = Map::new();
    raw.insert("v".to_string(), Value::Number(Number::from(RECORD_VERSION)));
    raw.insert("kind".to_string(), Value::String(params.kind.to_string()));
    raw.insert("run".to_string(), Value::String(params.run.to_string()));
    raw.insert(
        "task".to_string(),
        params
            .task
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    raw.insert(
        "dispatch".to_string(),
        params
            .dispatch
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    raw.insert(
        "epoch".to_string(),
        Value::Number(Number::from(params.epoch)),
    );
    raw.insert(
        "producer".to_string(),
        Value::String(params.producer.to_string()),
    );
    raw.insert("clock".to_string(), Value::String(params.clock.to_string()));
    raw.insert("basis".to_string(), Value::String(params.basis.to_string()));
    raw.insert(
        "observed_at".to_string(),
        Value::String(params.observed_at.to_string()),
    );
    raw.insert("data".to_string(), data_val);
    let mut source = Map::new();
    source.insert(
        "ref".to_string(),
        Value::String(params.source_ref.to_string()),
    );
    source.insert(
        "sha256".to_string(),
        params
            .source_sha256
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    raw.insert("source".to_string(), Value::Object(source));
    raw.insert(
        "event_id".to_string(),
        Value::String(eid_initial.to_string()),
    );

    let mut event = normalize(&Value::Object(raw), true)?;
    if params.event_id.is_none() {
        let cid = content_id(&event);
        event.insert("event_id".to_string(), Value::String(cid));
    }
    Ok(event)
}

// ---------------------------------------------------------------------------- the record

fn raw_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    body.split('\n').collect()
}

fn create_parent_dir_0700(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn flock_exclusive(file: &fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    loop {
        if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub fn append_events(
    path: &Path,
    events: &[Map<String, Value>],
) -> Result<Vec<(String, &'static str)>, EventsError> {
    create_parent_dir_0700(path).map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;

    let mut opts = OpenOptions::new();
    opts.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut fh = opts.open(path).map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;

    #[cfg(unix)]
    flock_exclusive(&fh).map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;

    fh.seek(SeekFrom::Start(0)).map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    fh.read_to_end(&mut bytes).map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;
    let text = String::from_utf8(bytes).map_err(|err| {
        EventsError::FailClosed(format!("{} is not valid UTF-8: {err}", path.display()))
    })?;

    let lines = raw_lines(&text);
    for (idx, &raw) in lines.iter().enumerate() {
        let lineno = idx + 1;
        if raw.is_empty() || raw != raw.trim() {
            return Err(EventsError::FailClosed(format!(
                "{}:{lineno}: blank or padded line in event record",
                path.display()
            )));
        }
    }

    if !text.is_empty() && !text.ends_with('\n') {
        fh.write_all(b"\n").map_err(|err| {
            EventsError::FailClosed(format!(
                "event could not be written to {}: {err}",
                path.display()
            ))
        })?;
    }

    let mut known: HashMap<String, String> = HashMap::new();
    for &raw in &lines {
        if let Ok(Value::Object(rec)) = serde_json::from_str::<Value>(raw) {
            if let Some(Value::String(eid)) = rec.get("event_id") {
                let mut fields_only = Map::new();
                for &k in FIELDS {
                    fields_only.insert(k.to_string(), rec.get(k).cloned().unwrap_or(Value::Null));
                }
                if let Ok(ident) = identity(&fields_only) {
                    known.entry(eid.clone()).or_insert(ident);
                }
            }
        }
    }

    let mut previous: Option<String> = lines.last().map(|s| (*s).to_string());
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        let eid = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let ident = identity(event).map_err(EventsError::FailClosed)?;
        let seen = known.get(&eid).cloned();
        if seen.as_deref() == Some(ident.as_str()) {
            out.push((eid, "duplicate"));
            continue;
        }
        let mut record = event.clone();
        let prev_hash = match &previous {
            None => String::new(),
            Some(p) => sha256_hex(p),
        };
        record.insert("prev".to_string(), Value::String(prev_hash));
        let raw = py_canonical_json(&Value::Object(record));
        fh.write_all(raw.as_bytes())
            .and_then(|()| fh.write_all(b"\n"))
            .map_err(|err| {
                EventsError::FailClosed(format!(
                    "event could not be written to {}: {err}",
                    path.display()
                ))
            })?;
        previous = Some(raw);
        known.entry(eid.clone()).or_insert(ident);
        out.push((
            eid,
            if seen.is_none() {
                "appended"
            } else {
                "conflict"
            },
        ));
    }

    fh.flush().map_err(|err| {
        EventsError::FailClosed(format!(
            "event could not be written to {}: {err}",
            path.display()
        ))
    })?;
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub fields: Map<String, Value>,
    pub pos: usize,
    pub digest: String,
    pub at: DateTime<Utc>,
}

impl LogEvent {
    pub fn kind(&self) -> &str {
        self.fields["kind"].as_str().unwrap_or("")
    }

    pub fn event_id(&self) -> &str {
        self.fields["event_id"].as_str().unwrap_or("")
    }

    pub fn run(&self) -> &str {
        self.fields["run"].as_str().unwrap_or("")
    }

    pub fn task(&self) -> Option<&str> {
        self.fields.get("task").and_then(Value::as_str)
    }

    pub fn dispatch(&self) -> Option<&str> {
        self.fields.get("dispatch").and_then(Value::as_str)
    }

    pub fn epoch(&self) -> i64 {
        self.fields["epoch"].as_i64().unwrap_or(0)
    }

    pub fn observed_at(&self) -> &str {
        self.fields["observed_at"].as_str().unwrap_or("")
    }

    pub fn clock(&self) -> &str {
        self.fields["clock"].as_str().unwrap_or("")
    }

    pub fn basis(&self) -> &str {
        self.fields["basis"].as_str().unwrap_or("")
    }

    pub fn source(&self) -> &Value {
        &self.fields["source"]
    }

    pub fn source_ref(&self) -> &str {
        self.fields["source"]["ref"].as_str().unwrap_or("")
    }

    pub fn data(&self) -> &Map<String, Value> {
        self.fields["data"].as_object().expect("data object")
    }

    pub fn data_str(&self, key: &str) -> Option<&str> {
        self.data().get(key).and_then(Value::as_str)
    }

    pub fn data_i64(&self, key: &str) -> Option<i64> {
        self.data().get(key).and_then(Value::as_i64)
    }

    pub fn data_ids(&self, key: &str) -> Vec<String> {
        self.data()
            .get(key)
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn parse_instant(observed_at: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(observed_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| format!("invalid timestamp {observed_at:?}: {err}"))
}

pub fn read_log(path: &Path) -> Result<(Vec<LogEvent>, String, String), EventsError> {
    let data = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            EventsError::FailClosed(format!("{}: no event record", path.display()))
        } else {
            EventsError::FailClosed(format!("{} is unreadable: {err}", path.display()))
        }
    })?;
    let text = std::str::from_utf8(&data).map_err(|err| {
        EventsError::FailClosed(format!("{} is not valid UTF-8: {err}", path.display()))
    })?;

    let mut events = Vec::new();
    let mut previous: Option<&str> = None;
    for (idx, raw) in raw_lines(text).into_iter().enumerate() {
        let lineno = idx + 1;
        if raw.is_empty() || raw != raw.trim() {
            return Err(EventsError::FailClosed(format!(
                "{}:{lineno}: unparseable line or missing prev",
                path.display()
            )));
        }
        let parsed: Option<Value> = serde_json::from_str(raw).ok();
        let Some(Value::Object(mut record)) = parsed else {
            return Err(EventsError::FailClosed(format!(
                "{}:{lineno}: unparseable line or missing prev",
                path.display()
            )));
        };
        let Some(Value::String(prev)) = record.remove("prev") else {
            return Err(EventsError::FailClosed(format!(
                "{}:{lineno}: unparseable line or missing prev",
                path.display()
            )));
        };
        let expected = match previous {
            None => String::new(),
            Some(p) => sha256_hex(p),
        };
        if prev != expected {
            return Err(EventsError::FailClosed(format!(
                "{}:{lineno}: prev does not match the previous raw line — the record was edited, reordered or truncated",
                path.display()
            )));
        }
        let normalized = normalize(&Value::Object(record), false).map_err(|err| {
            EventsError::FailClosed(format!("{}:{lineno}: {err}", path.display()))
        })?;
        let at = parse_instant(
            normalized
                .get("observed_at")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .map_err(|err| EventsError::FailClosed(format!("{}:{lineno}: {err}", path.display())))?;
        events.push(LogEvent {
            fields: normalized,
            pos: lineno,
            digest: sha256_hex(raw),
            at,
        });
        previous = Some(raw);
    }

    let file_sha = sha256_hex_bytes(&data);
    let head = match previous {
        None => String::new(),
        Some(p) => sha256_hex(p),
    };
    Ok((events, file_sha, head))
}

pub fn check_anchor(
    events: &[LogEvent],
    head: &str,
    expect_head: Option<&str>,
    expect_ancestor: Option<&str>,
) -> Option<String> {
    if let Some(anc) = expect_ancestor {
        let want = anc.trim().to_ascii_lowercase();
        if !want.is_empty() && !events.iter().any(|e| e.digest == want) {
            return Some(format!(
                "the anchored head {want} is not in this record — a rewritten or truncated record loses the anchored line"
            ));
        }
    }
    if let Some(eh) = expect_head {
        let want = eh.trim().to_ascii_lowercase();
        if want != head {
            let actual_shown = if head.is_empty() { "(empty)" } else { head };
            let want_shown = if want.is_empty() {
                "(empty)"
            } else {
                want.as_str()
            };
            return Some(format!(
                "the record's head is {actual_shown}, not the anchored {want_shown}"
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------- derivation

fn na_val(reasons: &[String]) -> Value {
    let unique: Vec<String> = reasons
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    json!({
        "value": Value::Null,
        UNAVAILABLE: unique,
    })
}

fn short_sha(sha: Option<&str>) -> &str {
    match sha {
        Some(s) if !s.is_empty() => &s[..s.len().min(12)],
        _ => "(unnamed head)",
    }
}

pub fn interval(start: &LogEvent, end: &LogEvent, what: &str) -> Result<Frac, String> {
    if start.clock() != end.clock() {
        return Err(format!(
            "{what}: {} and {} are on different clocks ({}, {}); no common clock, no interval",
            start.kind(),
            end.kind(),
            start.clock(),
            end.clock()
        ));
    }
    for event in [start, end] {
        if event.basis() == "recovered" {
            return Err(format!(
                "{what}: {} was recovered after a coordinator resume, so its time is when it was rebuilt, not when it happened",
                event.kind()
            ));
        }
    }
    let start_ns = i128::from(start.at.timestamp()) * 1_000_000_000
        + i128::from(start.at.timestamp_subsec_nanos());
    let end_ns = i128::from(end.at.timestamp()) * 1_000_000_000
        + i128::from(end.at.timestamp_subsec_nanos());
    let seconds = Frac::new(end_ns - start_ns, 1_000_000_000);
    if seconds.num < 0 {
        return Err(format!(
            "{what}: negative on clock {} ({}s) — the clock stepped back or the events are misattributed; never clamped to 0",
            start.clock(),
            format_decimal_half_even(seconds, 2)
        ));
    }
    Ok(seconds)
}

pub fn first<'a>(events: &[&'a LogEvent], what: &str) -> Result<&'a LogEvent, String> {
    if events.len() == 1 {
        return Ok(events[0]);
    }
    let clocks: HashSet<&str> = events.iter().map(|e| e.clock()).collect();
    if clocks.len() > 1 {
        return Err(format!(
            "{what}: {} observations on different clocks; none is provably first",
            events.len()
        ));
    }
    let best = events
        .iter()
        .copied()
        .min_by_key(|e| (e.at, e.pos))
        .expect("non-empty events");
    Ok(best)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Scope {
    Run,
    Wave(i64),
    Usage,
    Unit(String),
}

fn scope_of(event: &LogEvent) -> Scope {
    if DECLARES_EPOCH.contains(&event.kind()) {
        Scope::Run
    } else if matches!(event.kind(), "wave.open" | "wave.close") {
        Scope::Wave(event.data_i64("wave").unwrap_or(0))
    } else if event.kind() == "model.usage" {
        Scope::Usage
    } else {
        Scope::Unit(event.task().unwrap_or("").to_string())
    }
}

struct ScreenResult<'a> {
    kept: Vec<&'a LogEvent>,
    duplicates: usize,
    conflicts: Vec<Value>,
    fenced: Vec<Value>,
    epochs: Vec<Value>,
    taints: HashMap<Scope, Vec<String>>,
    excluded: Vec<&'a LogEvent>,
}

fn screen<'a>(in_run: &HashSet<usize>, all_events: &'a [LogEvent]) -> ScreenResult<'a> {
    let mut by_id: HashMap<&'a str, (usize, &'a LogEvent, String)> = HashMap::new();
    let mut kept_raw: Vec<&'a LogEvent> = Vec::new();
    let mut duplicates = 0usize;
    let mut conflicts: Vec<Value> = Vec::new();
    let mut taints: HashMap<Scope, Vec<String>> = HashMap::new();
    let mut excluded: Vec<&'a LogEvent> = Vec::new();

    for (idx, event) in all_events.iter().enumerate() {
        let ev_ident = identity(&event.fields).unwrap_or_default();
        if let Some(&(seen_idx, seen, ref seen_ident)) = by_id.get(event.event_id()) {
            if seen_ident == &ev_ident {
                if in_run.contains(&idx) {
                    duplicates += 1;
                }
            } else if in_run.contains(&seen_idx) || in_run.contains(&idx) {
                conflicts.push(json!({
                    "event_id": event.event_id(),
                    "kept": seen.digest,
                    "conflicting": event.digest,
                }));
                let why = format!(
                    "event_id {} delivered twice with different bodies (contested observation)",
                    event.event_id()
                );
                if in_run.contains(&seen_idx) {
                    taints.entry(scope_of(seen)).or_default().push(why.clone());
                }
                if in_run.contains(&idx) {
                    taints.entry(scope_of(event)).or_default().push(why.clone());
                    excluded.push(event);
                }
                if seen.run() != event.run() {
                    taints.entry(Scope::Run).or_default().push(why);
                }
            }
        } else {
            by_id.insert(event.event_id(), (idx, event, ev_ident));
            if in_run.contains(&idx) {
                kept_raw.push(event);
            }
        }
    }

    let mut declared = 0i64;
    let mut screened: Vec<&'a LogEvent> = Vec::new();
    let mut fenced: Vec<Value> = Vec::new();
    let mut epochs: Vec<Value> = Vec::new();

    for event in kept_raw {
        if DECLARES_EPOCH.contains(&event.kind()) {
            if event.epoch() <= declared {
                let why = format!(
                    "{} declares epoch {} after epoch {declared} was declared — a stale or duplicate coordinator",
                    event.kind(),
                    event.epoch()
                );
                fenced.push(json!({
                    "digest": event.digest,
                    "epoch": event.epoch(),
                    "declared": declared,
                    "reason": why,
                }));
                taints.entry(scope_of(event)).or_default().push(why);
                excluded.push(event);
                continue;
            }
            let expected = if declared == 0 {
                ("run.start", 1i64)
            } else {
                ("coordinator.resume", declared + 1)
            };
            if (event.kind(), event.epoch()) != expected {
                let why = format!(
                    "{} declares epoch {} where {} at epoch {} was due — coordinator history is missing",
                    event.kind(),
                    event.epoch(),
                    expected.0,
                    expected.1
                );
                taints.entry(scope_of(event)).or_default().push(why);
            }
            declared = event.epoch();
            epochs.push(json!({
                "epoch": event.epoch(),
                "kind": event.kind(),
                "coordinator": event.data_str("coordinator").unwrap_or(""),
                "clock": event.clock(),
                "digest": event.digest,
            }));
            screened.push(event);
            continue;
        }
        if event.epoch() != declared {
            let why = if event.epoch() < declared {
                format!(
                    "{} recorded under epoch {} after epoch {declared} was declared — a fenced coordinator's write",
                    event.kind(),
                    event.epoch()
                )
            } else {
                format!(
                    "{} recorded under epoch {}, which no run.start or coordinator.resume declared before it",
                    event.kind(),
                    event.epoch()
                )
            };
            fenced.push(json!({
                "digest": event.digest,
                "epoch": event.epoch(),
                "declared": declared,
                "reason": why,
            }));
            taints.entry(scope_of(event)).or_default().push(why);
            excluded.push(event);
            continue;
        }
        screened.push(event);
    }

    ScreenResult {
        kept: screened,
        duplicates,
        conflicts,
        fenced,
        epochs,
        taints,
        excluded,
    }
}

pub fn launch_attempt(event: &LogEvent) -> Option<&str> {
    let disp = event.dispatch()?;
    let expected = format!("local-state:dispatches/{disp}");
    if event.source_ref() == expected {
        Some(event.observed_at())
    } else {
        None
    }
}

struct LatencyOutcome {
    seconds: Option<Frac>,
    unavailable: Option<String>,
    excluded: Option<String>,
}

struct UnitDerived<'a> {
    task: String,
    outcome: &'static str,
    carried_out: bool,
    task_completed: bool,
    park_classes: Vec<String>,
    dispatches: Vec<String>,
    dispatched_before: Vec<String>,
    unlaunched: Vec<String>,
    retries: usize,
    bounced: bool,
    approvals: usize,
    voided_reviews: Vec<String>,
    latency: LatencyOutcome,
    ended: Vec<String>,
    queue: Vec<Result<Frac, String>>,
    rereviewed: Vec<String>,
    contested: Vec<String>,
    close_head: Option<String>,
    close_tree: Option<String>,
    verified_at: Vec<String>,
    done_at: Vec<String>,
    reviewed: Vec<String>,
    events: Vec<&'a LogEvent>,
}

fn group_by_kind<'a>(events: &[&'a LogEvent]) -> HashMap<&'static str, Vec<&'a LogEvent>> {
    let mut by: HashMap<&'static str, Vec<&'a LogEvent>> = HashMap::new();
    for &k in KINDS {
        by.insert(k, Vec::new());
    }
    for &e in events {
        if let Some(bucket) = by.get_mut(e.kind()) {
            bucket.push(e);
        }
    }
    by
}

fn derive_unit<'a>(
    task: &str,
    events: &[&'a LogEvent],
    history: &[&'a LogEvent],
    carried_out: bool,
    ended_before_arg: &HashSet<String>,
    counted_voids: &HashSet<String>,
) -> UnitDerived<'a> {
    let by = group_by_kind(events);
    let past = group_by_kind(history);
    let mut contested: Vec<String> = Vec::new();

    let launched: BTreeSet<String> = by["dispatch.launched"]
        .iter()
        .filter_map(|e| e.dispatch().map(ToString::to_string))
        .collect();
    let mut seen: BTreeSet<String> = launched.clone();
    for e in by["task.done"].iter().chain(by["dispatch.died"].iter()) {
        if let Some(d) = e.dispatch() {
            seen.insert(d.to_string());
        }
    }
    let past_launched: BTreeSet<String> = past["dispatch.launched"]
        .iter()
        .filter_map(|e| e.dispatch().map(ToString::to_string))
        .collect();
    let mut past_seen: BTreeSet<String> = past_launched.clone();
    for e in past["task.done"].iter().chain(past["dispatch.died"].iter()) {
        if let Some(d) = e.dispatch() {
            past_seen.insert(d.to_string());
        }
    }

    let passes: Vec<&'a LogEvent> = by["verify.verdict"]
        .iter()
        .copied()
        .filter(|e| e.data_i64("exit") == Some(0))
        .collect();
    let passed_before: HashSet<String> = past["verify.verdict"]
        .iter()
        .filter(|e| e.data_i64("exit") == Some(0))
        .filter_map(|e| e.data_str("head_sha").map(ToString::to_string))
        .collect();
    let mut ended_before: HashSet<String> = passed_before.clone();
    ended_before.extend(ended_before_arg.iter().cloned());

    let mut ended: BTreeSet<String> = passes
        .iter()
        .filter_map(|p| p.data_str("head_sha").map(ToString::to_string))
        .collect();

    let dones = &by["task.done"];
    let mut known_dones: Vec<&'a LogEvent> =
        Vec::with_capacity(dones.len() + past["task.done"].len());
    known_dones.extend_from_slice(dones);
    known_dones.extend_from_slice(&past["task.done"]);

    let closes = &by["unit.closed"];
    let close_heads: Vec<String> = closes
        .iter()
        .filter_map(|e| e.data_str("head_sha").map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if close_heads.len() > 1 {
        contested.push(format!(
            "unit {task}: closed at {} different heads",
            close_heads.len()
        ));
    }
    let close_head = if close_heads.len() == 1 {
        Some(close_heads[0].clone())
    } else {
        None
    };

    let close_trees: BTreeSet<String> = closes
        .iter()
        .filter_map(|e| e.data_str("head_wtree").map(ToString::to_string))
        .collect();
    if close_trees.len() > 1 {
        contested.push(format!(
            "unit {task}: closed with {} different trees",
            close_trees.len()
        ));
    }
    let close_tree = if close_trees.len() == 1 {
        close_trees.into_iter().next()
    } else {
        None
    };

    let outcome: &'static str = if !closes.is_empty() {
        let verified = close_head.as_deref().is_some_and(|ch| {
            passed_before.contains(ch) || passes.iter().any(|p| p.data_str("head_sha") == Some(ch))
        });
        if verified {
            "verified-closed"
        } else {
            "closed-unverified"
        }
    } else if !by["unit.parked"].is_empty() {
        "parked"
    } else if !passes.is_empty() {
        "verified"
    } else if !dones.is_empty() {
        "completed"
    } else {
        "open"
    };

    // Verification latency
    let mut latency = LatencyOutcome {
        seconds: None,
        unavailable: None,
        excluded: None,
    };
    let ended_there = format!(
        "unit {task}: its latency ended in an earlier wave (a pass or a park at its head), which measured it"
    );
    let mut head: Option<String> = None;
    let mut ends: Vec<&'a LogEvent> = Vec::new();
    if matches!(outcome, "verified-closed" | "verified") {
        let done_heads: HashSet<String> = known_dones
            .iter()
            .filter_map(|d| d.data_str("head_sha").map(ToString::to_string))
            .collect();
        let bound_here: HashSet<String> = passes
            .iter()
            .filter_map(|p| p.data_str("head_sha").map(ToString::to_string))
            .collect();
        let mut heads: Vec<String> = bound_here
            .iter()
            .filter(|h| !ended_before.contains(h.as_str()) && done_heads.contains(h.as_str()))
            .cloned()
            .collect();
        heads.sort();
        if heads.len() == 1 {
            let h = heads.remove(0);
            ends = passes
                .iter()
                .copied()
                .filter(|p| p.data_str("head_sha") == Some(h.as_str()))
                .collect();
            head = Some(h);
        } else if (!bound_here.is_empty()
            || close_head
                .as_deref()
                .is_some_and(|ch| passed_before.contains(ch)))
            && bound_here.is_subset(&ended_before)
            && passes.iter().all(|p| p.data_str("head_sha").is_some())
        {
            latency.excluded = Some(ended_there);
        } else if known_dones.is_empty() {
            latency.unavailable = Some(format!(
                "unit {task}: verified without an observed worker_done"
            ));
        } else {
            latency.unavailable = Some(format!(
                "unit {task}: a passing verdict at {} head(s) a worker reported done; which pair is its latency is ambiguous",
                heads.len()
            ));
        }
    } else if outcome == "parked" {
        ends = by["unit.parked"].clone();
        let park_heads: BTreeSet<Option<String>> = ends
            .iter()
            .map(|p| p.data_str("head_sha").map(ToString::to_string))
            .collect();
        head = if park_heads.len() == 1 {
            park_heads.into_iter().next().flatten()
        } else {
            None
        };
        if head.as_deref().is_some_and(|h| ended_before.contains(h)) {
            latency.excluded = Some(ended_there);
            ends.clear();
        }
    } else if carried_out {
        latency.excluded = Some(format!(
            "unit {task}: carried into a later wave before it verified or parked here, so its latency is that wave's"
        ));
    } else {
        latency.unavailable = Some(format!(
            "unit {task}: no verified-or-parked observation ({outcome})"
        ));
    }

    if !ends.is_empty() && latency.unavailable.is_none() {
        let starts: Vec<&'a LogEvent> = if let Some(ref h) = head {
            known_dones
                .iter()
                .copied()
                .filter(|d| d.data_str("head_sha") == Some(h.as_str()))
                .collect()
        } else if !dones.is_empty() {
            dones.clone()
        } else {
            past["task.done"]
                .iter()
                .copied()
                .filter(|d| {
                    d.data_str("head_sha")
                        .is_none_or(|h| !ended_before.contains(h))
                })
                .collect()
        };
        if starts.is_empty() && outcome == "parked" && known_dones.is_empty() {
            latency.excluded = Some(format!(
                "unit {task}: parked with no worker_done, so it has no latency"
            ));
        } else if starts.is_empty() {
            latency.unavailable = Some(format!(
                "unit {task}: no worker_done observed at {}",
                short_sha(head.as_deref())
            ));
        } else {
            let start_heads: HashSet<Option<&str>> =
                starts.iter().map(|d| d.data_str("head_sha")).collect();
            if start_heads.len() > 1 {
                latency.unavailable = Some(format!(
                    "unit {task}: worker_done at several heads and the park names none; which one it ends is ambiguous"
                ));
            } else {
                if let Some(h) = starts[0].data_str("head_sha") {
                    ended.insert(h.to_string());
                }
                let start_res = first(&starts, &format!("unit {task} worker_done"));
                let end_res = first(&ends, &format!("unit {task} {}", ends[0].kind()));
                match (start_res, end_res) {
                    (Err(why), _) => latency.unavailable = Some(why),
                    (_, Err(why)) => latency.unavailable = Some(why),
                    (Ok(st), Ok(en)) => match interval(st, en, &format!("unit {task} latency")) {
                        Ok(secs) => latency.seconds = Some(secs),
                        Err(why) => latency.unavailable = Some(why),
                    },
                }
            }
        }
    }

    // Review queue
    let mut queue: Vec<Result<Frac, String>> = Vec::new();
    let started_before: HashSet<String> = past["review.started"]
        .iter()
        .filter_map(|e| e.data_str("head_sha").map(ToString::to_string))
        .collect();
    let rereviewed: Vec<String> = by["review.started"]
        .iter()
        .filter_map(|e| e.data_str("head_sha").map(ToString::to_string))
        .filter(|h| started_before.contains(h.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut started: BTreeMap<String, Vec<&'a LogEvent>> = BTreeMap::new();
    for &event in &by["review.started"] {
        if let Some(h) = event.data_str("head_sha") {
            if !started_before.contains(h) {
                started.entry(h.to_string()).or_default().push(event);
            }
        }
    }
    for (sha, evs) in &started {
        let at_head: Vec<&'a LogEvent> = known_dones
            .iter()
            .copied()
            .filter(|d| d.data_str("head_sha") == Some(sha.as_str()))
            .collect();
        if at_head.is_empty() {
            queue.push(Err(format!(
                "unit {task}: review started at {} with no worker_done observed at that head",
                short_sha(Some(sha.as_str()))
            )));
            continue;
        }
        let st_res = first(&at_head, &format!("unit {task} worker_done"));
        let en_res = first(evs, &format!("unit {task} review.started"));
        match (st_res, en_res) {
            (Err(why), _) | (_, Err(why)) => queue.push(Err(why)),
            (Ok(st), Ok(en)) => queue.push(interval(st, en, &format!("unit {task} review queue"))),
        }
    }

    // Freshness
    let voided_before: HashSet<String> = past["review.voided"]
        .iter()
        .filter_map(|v| v.data_str("reviewed_sha").map(ToString::to_string))
        .collect();
    let mut approvals: Vec<&'a LogEvent> = by["review.verdict"]
        .iter()
        .copied()
        .filter(|r| r.data_str("verdict") == Some("approve"))
        .collect();
    if past["unit.closed"].is_empty() {
        for &r in &past["review.verdict"] {
            if r.data_str("verdict") == Some("approve") {
                if let Some(rsha) = r.data_str("reviewed_sha") {
                    if !voided_before.contains(rsha) {
                        approvals.push(r);
                    }
                }
            }
        }
    }
    let mut reviews: BTreeMap<(String, String), &'a LogEvent> = BTreeMap::new();
    for &review in &approvals {
        let rsha = review.data_str("reviewed_sha").unwrap_or("").to_string();
        let key = match review.dispatch() {
            Some(d) => (d.to_string(), rsha),
            None => ("event".to_string(), review.event_id().to_string()),
        };
        reviews.entry(key).or_insert(review);
    }
    let explicit: BTreeSet<String> = by["review.voided"]
        .iter()
        .filter_map(|v| v.data_str("reviewed_sha").map(ToString::to_string))
        .collect();
    let mut voided: Vec<String> = Vec::new();
    for review in reviews.values() {
        let sha = review.data_str("reviewed_sha").unwrap_or("");
        let tree = review.data_str("reviewed_wtree");
        let moved = close_head
            .as_deref()
            .is_some_and(|ch| sha != ch && !(tree.is_some() && tree == close_tree.as_deref()));
        if moved || explicit.contains(sha) {
            voided.push(sha.to_string());
        }
    }
    let approved_shas: HashSet<&str> = approvals
        .iter()
        .filter_map(|r| r.data_str("reviewed_sha"))
        .collect();
    for sha in &explicit {
        if !approved_shas.contains(sha.as_str()) && !counted_voids.contains(sha.as_str()) {
            voided.push(sha.clone());
        }
    }
    voided.sort();

    // Retries
    let mut named: HashMap<&str, HashSet<&str>> = HashMap::new();
    for &e in by["dispatch.launched"]
        .iter()
        .chain(past["dispatch.launched"].iter())
    {
        if let (Some(d), Some(la)) = (e.dispatch(), launch_attempt(e)) {
            named.entry(d).or_default().insert(la);
        }
    }
    let attempts =
        |launches: &[&'a LogEvent], ids: &BTreeSet<String>| -> HashSet<(String, Option<String>)> {
            let mut keys: HashSet<(String, Option<String>)> = HashSet::new();
            for &e in launches {
                if let Some(d) = e.dispatch() {
                    let la = launch_attempt(e);
                    if la.is_some() || !named.contains_key(d) {
                        keys.insert((d.to_string(), la.map(ToString::to_string)));
                    }
                }
            }
            for d in ids {
                if !launched.contains(d) && !past_launched.contains(d) {
                    keys.insert((d.clone(), None));
                }
            }
            keys
        };
    let before = attempts(&past["dispatch.launched"], &past_seen);
    let current = attempts(&by["dispatch.launched"], &seen);
    let fresh_count = current.difference(&before).count();
    let retries = fresh_count.saturating_sub(if before.is_empty() { 1 } else { 0 });

    let unlaunched: Vec<String> = seen
        .iter()
        .filter(|d| !launched.contains(*d) && !past_launched.contains(*d))
        .cloned()
        .collect();
    let bounced = !by["unit.suspect"].is_empty()
        || retries > 0
        || by["verify.verdict"]
            .iter()
            .any(|v| v.data_i64("exit") == Some(2));
    let park_classes: Vec<String> = by["unit.parked"]
        .iter()
        .filter_map(|p| p.data_str("park_class").map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let verified_at: Vec<String> = passes
        .iter()
        .filter_map(|p| p.data_str("head_sha").map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let done_at: Vec<String> = dones
        .iter()
        .filter_map(|d| d.data_str("head_sha").map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let reviewed: Vec<String> = by["review.verdict"]
        .iter()
        .filter_map(|r| r.data_str("reviewed_sha").map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut sorted_events = events.to_vec();
    sorted_events.sort_by_key(|e| e.pos);

    UnitDerived {
        task: task.to_string(),
        outcome,
        carried_out,
        task_completed: !dones.is_empty(),
        park_classes,
        dispatches: seen.into_iter().collect(),
        dispatched_before: past_seen.into_iter().collect(),
        unlaunched,
        retries,
        bounced,
        approvals: reviews.len(),
        voided_reviews: voided,
        latency,
        ended: ended.into_iter().collect(),
        queue,
        rereviewed,
        contested,
        close_head,
        close_tree,
        verified_at,
        done_at,
        reviewed,
        events: sorted_events,
    }
}

fn wave_metrics(
    k: i64,
    opened: Option<&LogEvent>,
    closed: Option<&LogEvent>,
    units: &[&UnitDerived<'_>],
) -> BTreeMap<String, Value> {
    let mut metrics: BTreeMap<String, Value> = BTreeMap::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut wall: Option<Frac> = None;
    if opened.is_none() {
        reasons.push(format!("wave {k}: wave.open not observed"));
    }
    if closed.is_none() {
        reasons.push(format!(
            "wave {k}: wave.close not observed, so the wall-clock is unknown"
        ));
    }
    if let (Some(op), Some(cl)) = (opened, closed) {
        match interval(op, cl, &format!("wave {k} wall-clock")) {
            Err(why) => reasons.push(why),
            Ok(w) if w.num == 0 => reasons.push(format!("wave {k}: zero wall-clock")),
            Ok(w) => wall = Some(w),
        }
    }
    if units.is_empty() {
        reasons.push(format!("wave {k}: no planned unit"));
    }
    let pending: Vec<String> = units
        .iter()
        .filter(|u| !CLOSED_OR_PARKED.contains(&u.outcome) && !u.carried_out)
        .map(|u| u.task.clone())
        .collect();
    if !pending.is_empty() {
        reasons.push(format!(
            "wave {k}: {} not observed CLOSED or parked — a pending or unrecorded close would change the count",
            py_list_str(&pending)
        ));
    }
    let closed_n = units
        .iter()
        .filter(|u| u.outcome == "verified-closed")
        .count();
    let throughput = if !reasons.is_empty() {
        na_val(&reasons)
    } else {
        let w = wall.expect("wall set when no reasons");
        let rate = Frac::from_int((closed_n as i128) * 3600).div_frac(w);
        json!({
            "value": format!("{}/h", format_decimal_half_even(rate, 2)),
            "verified_closed": closed_n,
            "wall_clock_s": w.to_string(),
        })
    };
    metrics.insert("throughput".to_string(), throughput);

    let mut lat: Vec<Frac> = Vec::new();
    let mut lat_reasons: Vec<String> = Vec::new();
    for u in units {
        if u.latency.excluded.is_some() {
            continue;
        }
        if let Some(secs) = u.latency.seconds {
            lat.push(secs);
        } else if let Some(ref why) = u.latency.unavailable {
            lat_reasons.push(why.clone());
        }
    }
    if lat.is_empty() && lat_reasons.is_empty() {
        lat_reasons.push(format!(
            "wave {k}: no unit reached verified-or-parked after an observed worker_done"
        ));
    }
    if !lat_reasons.is_empty() {
        let na = na_val(&lat_reasons);
        metrics.insert("latency_median".to_string(), na.clone());
        metrics.insert("latency_max".to_string(), na);
    } else {
        let max_lat = lat.iter().copied().max().expect("non-empty lat");
        metrics.insert(
            "latency_median".to_string(),
            json!({"value": minutes(median(&lat)), "units": lat.len()}),
        );
        metrics.insert(
            "latency_max".to_string(),
            json!({"value": minutes(max_lat), "units": lat.len()}),
        );
    }

    let open_units: Vec<String> = units
        .iter()
        .filter(|u| !LEFT_DISPATCHED.contains(&u.outcome) && !u.carried_out)
        .map(|u| u.task.clone())
        .collect();
    let rework = if units.is_empty() {
        na_val(&[format!("wave {k}: no planned unit")])
    } else if !open_units.is_empty() {
        na_val(&[format!(
            "wave {k}: {} not yet verified or parked — a later bounce could still land",
            py_list_str(&open_units)
        )])
    } else {
        let bounced = units.iter().filter(|u| u.bounced).count();
        json!({
            "value": format!("{bounced}/{}", units.len()),
            "bounced": bounced,
            "units": units.len(),
        })
    };
    metrics.insert("rework".to_string(), rework);

    let fresh_reasons: Vec<String> = if units.is_empty() {
        vec![format!("wave {k}: no planned unit")]
    } else if !pending.is_empty() {
        vec![format!(
            "wave {k}: {} not closed or parked; a review is voided at merge, which has not happened yet",
            py_list_str(&pending)
        )]
    } else {
        units
            .iter()
            .filter(|u| {
                matches!(u.outcome, "verified-closed" | "closed-unverified") && u.approvals == 0
            })
            .map(|u| {
                format!(
                    "unit {}: closed with no approving review observed, so its freshness cannot be judged",
                    u.task
                )
            })
            .collect()
    };
    let freshness = if !fresh_reasons.is_empty() {
        na_val(&fresh_reasons)
    } else {
        let total_voids: usize = units.iter().map(|u| u.voided_reviews.len()).sum();
        json!({"value": total_voids.to_string()})
    };
    metrics.insert("freshness".to_string(), freshness);

    let queue: Vec<&Result<Frac, String>> = units.iter().flat_map(|u| u.queue.iter()).collect();
    let mut queue_reasons: Vec<String> = queue
        .iter()
        .filter_map(|r| r.as_ref().err().cloned())
        .collect();
    if queue.is_empty() {
        let any_rereviewed = units.iter().any(|u| !u.rereviewed.is_empty());
        queue_reasons = vec![if !any_rereviewed {
            format!("wave {k}: no review.started observed")
        } else {
            format!("wave {k}: only re-reviews of heads an earlier wave measured")
        }];
    }
    if !queue_reasons.is_empty() {
        let na = na_val(&queue_reasons);
        metrics.insert("review_queue_median".to_string(), na.clone());
        metrics.insert("review_queue_max".to_string(), na);
    } else {
        let values: Vec<Frac> = queue
            .iter()
            .filter_map(|r| r.as_ref().ok().copied())
            .collect();
        let max_q = values.iter().copied().max().expect("non-empty queue");
        metrics.insert(
            "review_queue_median".to_string(),
            json!({"value": minutes(median(&values)), "reviews": values.len()}),
        );
        metrics.insert(
            "review_queue_max".to_string(),
            json!({"value": minutes(max_q), "reviews": values.len()}),
        );
    }

    let retry_reasons: Vec<String> = if units.is_empty() {
        vec![format!("wave {k}: no planned unit")]
    } else {
        let mut r: Vec<String> = units
            .iter()
            .filter(|u| u.dispatches.is_empty() && u.dispatched_before.is_empty())
            .map(|u| format!("unit {}: no dispatch observed", u.task))
            .collect();
        for u in units {
            if !u.unlaunched.is_empty() {
                r.push(format!(
                    "unit {}: dispatch(es) {} reported without an observed launch",
                    u.task,
                    py_list_str(&u.unlaunched)
                ));
            }
        }
        r
    };
    let retries = if !retry_reasons.is_empty() {
        na_val(&retry_reasons)
    } else {
        let total_retries: usize = units.iter().map(|u| u.retries).sum();
        json!({"value": total_retries.to_string()})
    };
    metrics.insert("retries".to_string(), retries);

    metrics
}

enum FieldAccum {
    Int(i128),
    Money(MoneyDecimal),
}

impl FieldAccum {
    fn zero(field: &str) -> Self {
        if field == "cost_usd" {
            Self::Money(MoneyDecimal::zero())
        } else {
            Self::Int(0)
        }
    }

    fn add_accum(&mut self, other: &Self) {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => *a += *b,
            (Self::Money(a), Self::Money(b)) => a.add_assign(b),
            _ => unreachable!("mismatched accum types"),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Int(n) => {
                if let Ok(i) = i64::try_from(*n) {
                    Value::Number(Number::from(i))
                } else {
                    Value::Number(Number::from(*n as u64))
                }
            }
            Self::Money(m) => Value::String(m.format_fixed()),
        }
    }
}

struct ModelAgg {
    observations: usize,
    provenance: BTreeSet<String>,
    fields: HashMap<&'static str, (FieldAccum, usize)>,
}

fn usage_summary(
    events: &[&LogEvent],
    dispatches: &[String],
    tainted: &[String],
    unsure: &[String],
    relaunched: &BTreeMap<String, Vec<String>>,
) -> Value {
    let mut models: BTreeMap<String, ModelAgg> = BTreeMap::new();
    for &event in events {
        let name = event
            .data_str("model")
            .filter(|s| !s.is_empty())
            .unwrap_or("(unreported)")
            .to_string();
        let agg = models.entry(name).or_insert_with(|| {
            let mut fields = HashMap::new();
            for &f in USAGE_FIELDS {
                fields.insert(f, (FieldAccum::zero(f), 0usize));
            }
            ModelAgg {
                observations: 0,
                provenance: BTreeSet::new(),
                fields,
            }
        });
        agg.observations += 1;
        if let Some(p) = event.data_str("provenance") {
            agg.provenance.insert(p.to_string());
        }
        for &field in USAGE_FIELDS {
            let entry = agg.fields.get_mut(field).expect("field");
            match event.data().get(field) {
                None | Some(Value::Null) => {
                    entry.1 += 1;
                }
                Some(Value::String(s)) if field == "cost_usd" => {
                    if let FieldAccum::Money(ref mut m) = entry.0 {
                        m.add_assign(&MoneyDecimal::parse(s));
                    }
                }
                Some(Value::Number(n)) => {
                    if let (FieldAccum::Int(ref mut sum), Some(v)) = (&mut entry.0, n.as_i64()) {
                        *sum += i128::from(v);
                    }
                }
                _ => {
                    entry.1 += 1;
                }
            }
        }
    }

    let mut out_models = Map::new();
    let mut totals: HashMap<&'static str, (FieldAccum, Vec<String>)> = HashMap::new();
    for &f in USAGE_FIELDS {
        totals.insert(f, (FieldAccum::zero(f), Vec::new()));
    }

    for (name, agg) in &models {
        let mut entry = Map::new();
        entry.insert(
            "observations".to_string(),
            Value::Number(Number::from(agg.observations)),
        );
        entry.insert(
            "provenance".to_string(),
            Value::Array(
                agg.provenance
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        for &field in USAGE_FIELDS {
            let (ref known, unknown) = agg.fields[field];
            let shown = known.to_json();
            if unknown > 0 {
                let partial = if unknown < agg.observations {
                    shown
                } else {
                    Value::Null
                };
                entry.insert(
                    field.to_string(),
                    json!({
                        "value": Value::Null,
                        "known_sum": partial,
                        UNAVAILABLE: format!("{unknown} of {} observation(s) did not report it", agg.observations),
                    }),
                );
                totals.get_mut(field).expect("field").1.push(format!(
                    "model {name}: {unknown} observation(s) did not report it"
                ));
            } else {
                entry.insert(field.to_string(), json!({"value": shown}));
            }
            totals.get_mut(field).expect("field").0.add_accum(known);
        }
        out_models.insert(name.clone(), Value::Object(entry));
    }

    let covered: HashSet<&str> = events.iter().filter_map(|e| e.dispatch()).collect();
    let unobserved: Vec<String> = dispatches
        .iter()
        .filter(|d| !covered.contains(d.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let unknown: Vec<String> = unsure
        .iter()
        .filter(|d| !covered.contains(d.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut shared: Vec<String> = Vec::new();
    for (did, tasks) in relaunched {
        let named: BTreeSet<String> = events
            .iter()
            .filter(|e| e.dispatch() == Some(did.as_str()))
            .filter_map(|e| e.task().map(ToString::to_string))
            .collect();
        let task_set: BTreeSet<String> = tasks.iter().cloned().collect();
        if task_set.len() < tasks.len() || !task_set.is_subset(&named) {
            let task_list: Vec<String> = task_set.into_iter().collect();
            let named_list: Vec<String> = named.into_iter().collect();
            shared.push(format!(
                "dispatch {did} was launched {} times under one id (tasks {}) and usage names task(s) {} only, so which launch each observation covers is unknown",
                tasks.len(),
                py_list_str(&task_list),
                py_list_str(&named_list)
            ));
        }
    }

    let mut run_total = Map::new();
    for &field in USAGE_FIELDS {
        let (ref known, ref field_reasons) = totals[field];
        let mut reasons = field_reasons.clone();
        if !unobserved.is_empty() {
            reasons.push(format!(
                "dispatch(es) {} have no usage observation",
                py_list_str(&unobserved)
            ));
        }
        if !unknown.is_empty() {
            reasons.push(format!(
                "dispatch(es) {} appear only in fenced or conflicting evidence and have no usage observation, so the run's usage coverage is unknown",
                py_list_str(&unknown)
            ));
        }
        reasons.extend(shared.iter().cloned());
        if events.is_empty() {
            reasons.push("no model.usage observed".to_string());
        }
        reasons.extend(tainted.iter().cloned());
        let total_val = if !reasons.is_empty() {
            na_val(&reasons)
        } else {
            json!({"value": known.to_json()})
        };
        run_total.insert(field.to_string(), total_val);
    }

    json!({
        "models": Value::Object(out_models),
        "unobserved_dispatches": unobserved,
        "run_total": Value::Object(run_total),
    })
}

fn row_text(k: i64, opened: Option<&LogEvent>, metrics: &BTreeMap<String, Value>) -> String {
    let builders = opened
        .and_then(|o| o.data_i64("builders"))
        .map(|n| n.to_string())
        .unwrap_or_else(|| UNAVAILABLE.to_string());
    let reviewers = opened
        .and_then(|o| o.data_i64("reviewers"))
        .map(|n| n.to_string())
        .unwrap_or_else(|| UNAVAILABLE.to_string());
    let cell = |m: &str| -> String {
        metrics
            .get(m)
            .and_then(|v| v.get("value"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(UNAVAILABLE)
            .to_string()
    };
    format!(
        "| `wave={k}` | `builders={builders} reviewers={reviewers}` | `throughput={}` | `latency_median={} latency_max={}` | `rework={}` | `freshness={}` |",
        cell("throughput"),
        cell("latency_median"),
        cell("latency_max"),
        cell("rework"),
        cell("freshness"),
    )
}

fn place(
    event: &LogEvent,
    ks: &[i64],
    boundary: &BTreeMap<i64, Option<&LogEvent>>,
) -> Result<i64, String> {
    if ks.len() == 1 {
        return Ok(ks[0]);
    }
    let what = format!(
        "unit {}: {} cannot be placed in wave {}..{}",
        event.task().unwrap_or(""),
        event.kind(),
        ks[0],
        ks[ks.len() - 1]
    );
    if event.basis() == "recovered" {
        return Err(format!(
            "{what} — its time is when it was rebuilt, not when it happened"
        ));
    }
    let mut placed = ks[0];
    for &k in &ks[1..] {
        let Some(Some(opened)) = boundary.get(&k) else {
            return Err(format!(
                "{what} — wave {k}'s wave.open is not observed on one clock"
            ));
        };
        if opened.clock() != event.clock() {
            return Err(format!(
                "{what} — it is on clock {}, wave {k}'s wave.open on {}",
                event.clock(),
                opened.clock()
            ));
        }
        if event.at >= opened.at {
            placed = k;
        }
    }
    let rebuilt: Vec<i64> = ks
        .iter()
        .copied()
        .filter(|&k| {
            k > placed
                && boundary
                    .get(&k)
                    .and_then(|o| *o)
                    .is_some_and(|o| o.basis() == "recovered")
        })
        .collect();
    if let Some(&first_rebuilt) = rebuilt.first() {
        return Err(format!(
            "{what} — wave {first_rebuilt}'s wave.open was recovered after a coordinator resume, so its time is when it was rebuilt and the event may be that wave's"
        ));
    }
    Ok(placed)
}

fn unit_view(unit: &UnitDerived<'_>) -> Value {
    let shown = if let Some(secs) = unit.latency.seconds {
        json!({"value": minutes(secs), "seconds": secs.to_string()})
    } else if let Some(ref excl) = unit.latency.excluded {
        json!({"value": Value::Null, "excluded": excl})
    } else {
        na_val(&[unit.latency.unavailable.clone().unwrap_or_default()])
    };
    let ev_views: Vec<Value> = unit
        .events
        .iter()
        .map(|e| {
            json!({
                "kind": e.kind(),
                "digest": e.digest,
                "source": e.source(),
            })
        })
        .collect();
    json!({
        "task": unit.task,
        "outcome": unit.outcome,
        "task_completed": unit.task_completed,
        "park_classes": unit.park_classes,
        "dispatches": unit.dispatches,
        "bounced": unit.bounced,
        "voided_reviews": unit.voided_reviews,
        "latency": shown,
        "revisions": {
            "closed_at": unit.close_head,
            "closed_tree": unit.close_tree,
            "verified_at": unit.verified_at,
            "done_at": unit.done_at,
            "reviewed": unit.reviewed,
        },
        "events": ev_views,
    })
}

pub fn derive(
    events: &[LogEvent],
    run: Option<&str>,
    file_sha: &str,
    head: &str,
) -> Result<Value, EventsError> {
    let runs: Vec<String> = events
        .iter()
        .map(|e| e.run().to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let run_id = match run {
        Some(r) => r.to_string(),
        None => {
            if runs.len() != 1 {
                return Err(EventsError::Usage(format!(
                    "the record holds {} run(s) {}; pass --run",
                    runs.len(),
                    py_list_str(&runs)
                )));
            }
            runs[0].clone()
        }
    };
    let in_run: HashSet<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.run() == run_id)
        .map(|(i, _)| i)
        .collect();
    if in_run.is_empty() {
        return Err(EventsError::Usage(format!(
            "the record holds no event for run {} (runs: {})",
            py_repr_str(&run_id),
            py_list_str(&runs)
        )));
    }
    let mine_count = in_run.len();
    let ScreenResult {
        kept,
        duplicates,
        conflicts,
        fenced,
        epochs,
        mut taints,
        excluded,
    } = screen(&in_run, events);

    if epochs.is_empty() {
        taints
            .entry(Scope::Run)
            .or_default()
            .push("no run.start observed, so no coordinator epoch was ever declared".to_string());
    }

    let mut opens: BTreeMap<i64, Vec<&LogEvent>> = BTreeMap::new();
    let mut closes: BTreeMap<i64, Vec<&LogEvent>> = BTreeMap::new();
    for &event in &kept {
        if event.kind() == "wave.open" {
            if let Some(w) = event.data_i64("wave") {
                opens.entry(w).or_default().push(event);
            }
        } else if event.kind() == "wave.close" {
            if let Some(w) = event.data_i64("wave") {
                closes.entry(w).or_default().push(event);
            }
        }
    }

    let mut plan: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for (&k, evs) in &opens {
        let plans: HashSet<String> = evs
            .iter()
            .map(|e| py_canonical_json(&e.fields["data"]))
            .collect();
        if plans.len() > 1 {
            taints.entry(Scope::Wave(k)).or_default().push(format!(
                "wave {k} opened with {} different plans",
                plans.len()
            ));
        }
        for task in evs[0].data_ids("tasks") {
            plan.entry(task).or_default().push(k);
        }
    }

    let carried: Vec<Value> = plan
        .iter()
        .filter(|(_, ks)| ks.len() > 1)
        .map(|(t, ks)| json!({"task": t, "waves": ks}))
        .collect();

    let mut lifecycle: BTreeMap<String, Vec<&LogEvent>> = BTreeMap::new();
    for &event in &kept {
        if let Some(task) = event.task() {
            if event.kind() != "model.usage" {
                lifecycle.entry(task.to_string()).or_default().push(event);
            }
        }
    }

    let mut boundary: BTreeMap<i64, Option<&LogEvent>> = BTreeMap::new();
    for (&k, evs) in &opens {
        boundary.insert(k, first(evs, &format!("wave {k} wave.open")).ok());
    }

    let mut units: BTreeMap<(String, i64), UnitDerived<'_>> = BTreeMap::new();
    for (task, ks) in &plan {
        let mut parts: BTreeMap<i64, Vec<&LogEvent>> =
            ks.iter().map(|&k| (k, Vec::new())).collect();
        if let Some(task_events) = lifecycle.get(task) {
            for &event in task_events {
                match place(event, ks, &boundary) {
                    Err(why) => {
                        taints
                            .entry(Scope::Unit(task.clone()))
                            .or_default()
                            .push(why);
                    }
                    Ok(k) => {
                        parts.entry(k).or_default().push(event);
                    }
                }
            }
        }
        let mut history: Vec<&LogEvent> = Vec::new();
        let mut ended: HashSet<String> = HashSet::new();
        let mut counted: HashSet<String> = HashSet::new();
        for (i, &k) in ks.iter().enumerate() {
            let part = parts.get(&k).map(Vec::as_slice).unwrap_or(&[]);
            let derived = derive_unit(task, part, &history, i + 1 < ks.len(), &ended, &counted);
            ended.extend(derived.ended.iter().cloned());
            counted.extend(derived.voided_reviews.iter().cloned());
            history.extend_from_slice(part);
            units.insert((task.clone(), k), derived);
        }
    }

    let unplanned: Vec<Value> = lifecycle
        .iter()
        .filter(|(t, _)| !plan.contains_key(t.as_str()))
        .map(|(t, evs)| json!({"task": t, "events": evs.len()}))
        .collect();

    let mut max_wave = 0i64;
    for &k in opens.keys().chain(closes.keys()) {
        max_wave = max_wave.max(k);
    }
    if !epochs.is_empty() {
        for scope in taints.keys() {
            if let Scope::Wave(k) = *scope {
                max_wave = max_wave.max(k);
            }
        }
    }

    let mut waves: Vec<Value> = Vec::new();
    for k in 1..=max_wave {
        let wave_units: Vec<&UnitDerived<'_>> = units
            .iter()
            .filter(|((_, wk), _)| *wk == k)
            .map(|(_, u)| u)
            .collect();
        let (opened, why_open) = match opens.get(&k) {
            Some(evs) => match first(evs, &format!("wave {k} wave.open")) {
                Ok(e) => (Some(e), None),
                Err(w) => (None, Some(w)),
            },
            None => (None, None),
        };
        let (closed, why_close) = match closes.get(&k) {
            Some(evs) => match first(evs, &format!("wave {k} wave.close")) {
                Ok(e) => (Some(e), None),
                Err(w) => (None, Some(w)),
            },
            None => (None, None),
        };
        let mut metrics = wave_metrics(k, opened, closed, &wave_units);
        if let Some(why) = why_open.or(why_close) {
            metrics.insert("throughput".to_string(), na_val(&[why]));
        }
        let mut reasons: Vec<String> = Vec::new();
        if let Some(r) = taints.get(&Scope::Run) {
            reasons.extend(r.iter().cloned());
        }
        if let Some(r) = taints.get(&Scope::Wave(k)) {
            reasons.extend(r.iter().cloned());
        }
        for u in &wave_units {
            if let Some(r) = taints.get(&Scope::Unit(u.task.clone())) {
                reasons.extend(r.iter().cloned());
            }
            reasons.extend(u.contested.iter().cloned());
        }
        if !reasons.is_empty() {
            let na = na_val(&reasons);
            for val in metrics.values_mut() {
                *val = na.clone();
            }
        }
        let mut outcomes = Map::new();
        for name in [
            "verified-closed",
            "closed-unverified",
            "parked",
            "verified",
            "completed",
            "open",
        ] {
            let count = wave_units.iter().filter(|u| u.outcome == name).count();
            outcomes.insert(name.to_string(), Value::Number(Number::from(count)));
        }
        let tc = wave_units.iter().filter(|u| u.task_completed).count();
        outcomes.insert(
            "task_completed".to_string(),
            Value::Number(Number::from(tc)),
        );

        let row = row_text(k, opened, &metrics);
        let metrics_obj: Map<String, Value> = metrics.into_iter().collect();
        let unit_views: Vec<Value> = wave_units.iter().map(|u| unit_view(u)).collect();
        waves.push(json!({
            "wave": k,
            "builders": opened.and_then(|o| o.data_i64("builders")),
            "reviewers": opened.and_then(|o| o.data_i64("reviewers")),
            "row": row,
            "metrics": Value::Object(metrics_obj),
            "outcomes": Value::Object(outcomes),
            "units": unit_views,
        }));
    }

    let dispatches: Vec<String> = kept
        .iter()
        .filter(|e| e.kind() != "model.usage")
        .filter_map(|e| e.dispatch().map(ToString::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let dispatch_set: HashSet<&str> = dispatches.iter().map(String::as_str).collect();
    let unsure: Vec<String> = excluded
        .iter()
        .filter(|e| e.kind() != "model.usage")
        .filter_map(|e| e.dispatch())
        .filter(|d| !dispatch_set.contains(d))
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut relaunched_map: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for &e in &kept {
        if e.kind() == "dispatch.launched" {
            if let (Some(d), Some(la), Some(t)) = (e.dispatch(), launch_attempt(e), e.task()) {
                relaunched_map
                    .entry(d.to_string())
                    .or_default()
                    .insert(la.to_string(), t.to_string());
            }
        }
    }
    let relaunched: BTreeMap<String, Vec<String>> = relaunched_map
        .into_iter()
        .filter(|(_, by_time)| by_time.len() > 1)
        .map(|(d, by_time)| (d, by_time.into_values().collect()))
        .collect();

    let usage_events: Vec<&LogEvent> = kept
        .iter()
        .copied()
        .filter(|e| e.kind() == "model.usage")
        .collect();
    let mut usage_tainted: Vec<String> = Vec::new();
    if let Some(r) = taints.get(&Scope::Usage) {
        usage_tainted.extend(r.iter().cloned());
    }
    if let Some(r) = taints.get(&Scope::Run) {
        usage_tainted.extend(r.iter().cloned());
    }
    let usage = usage_summary(
        &usage_events,
        &dispatches,
        &usage_tainted,
        &unsure,
        &relaunched,
    );

    let complete = !waves.is_empty()
        && waves.iter().all(|w| {
            ROW_METRICS.iter().all(|m| {
                w.get("metrics")
                    .and_then(|ms| ms.get(*m))
                    .and_then(|mv| mv.get("value"))
                    .is_some_and(|v| !v.is_null())
            })
        });

    let report = json!({
        "schema": REPORT_SCHEMA,
        "run": run_id,
        "record": {
            "log_sha256": file_sha,
            "head": head,
            "lines": events.len(),
            "run_events": kept.len(),
            "duplicates": duplicates,
            "conflicts": conflicts.len(),
            "fenced": fenced.len(),
            "other_run_events": events.len() - mine_count,
        },
        "epochs": epochs,
        "conflicts": conflicts,
        "fenced": fenced,
        "waves": waves,
        "unplanned": unplanned,
        "carried": carried,
        "usage": usage,
        "complete": complete,
    });
    Ok(redact(report))
}

pub fn render_markdown(report: &Value) -> String {
    let mut lines: Vec<String> = vec![
        "| Wave | WIP setting | Builder throughput | Verification latency | Rework rate | Freshness violations |".to_string(),
        "|---|---|---|---|---|---|".to_string(),
    ];
    let waves = report
        .get("waves")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for w in waves {
        if let Some(r) = w.get("row").and_then(Value::as_str) {
            lines.push(r.to_string());
        }
    }
    let rec = &report["record"];
    let head_str = rec["head"].as_str().unwrap_or("");
    let head_shown = if head_str.is_empty() {
        "(empty)"
    } else {
        head_str
    };
    lines.push(String::new());
    lines.push(format!(
        "Derived by `events.py report` for run `{}` from {} admitted event(s) of {} line(s) ({} duplicate(s) collapsed, {} conflict(s), {} fenced) — record sha256 `{}`, head `{head_shown}`.",
        report["run"].as_str().unwrap_or(""),
        rec["run_events"].as_u64().unwrap_or(0),
        rec["lines"].as_u64().unwrap_or(0),
        rec["duplicates"].as_u64().unwrap_or(0),
        rec["conflicts"].as_u64().unwrap_or(0),
        rec["fenced"].as_u64().unwrap_or(0),
        rec["log_sha256"].as_str().unwrap_or(""),
    ));
    let mut missing: Vec<(i64, &str, String)> = Vec::new();
    for w in waves {
        let wk = w["wave"].as_i64().unwrap_or(0);
        for &m in ROW_METRICS {
            let mv = &w["metrics"][m];
            if mv["value"].is_null() {
                if let Some(arr) = mv[UNAVAILABLE].as_array() {
                    for why in arr {
                        if let Some(s) = why.as_str() {
                            missing.push((wk, m, s.to_string()));
                        }
                    }
                }
            }
        }
    }
    if waves.is_empty() {
        lines.push(String::new());
        lines.push("No wave.open observed: the record carries no WIP-curve row.".to_string());
    }
    if !missing.is_empty() {
        lines.push(String::new());
        lines.push(
            "Unavailable — the record does not support a measured value, and none was estimated:"
                .to_string(),
        );
        for (k, m, why) in missing {
            lines.push(format!("- wave {k} `{m}`: {why}"));
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

pub fn derived_cells(report: &Value) -> BTreeMap<i64, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let waves = report
        .get("waves")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for wave in waves {
        let k = wave["wave"].as_i64().unwrap_or(0);
        let mut cells = BTreeMap::new();
        cells.insert("wave".to_string(), k.to_string());
        cells.insert(
            "builders".to_string(),
            wave["builders"]
                .as_i64()
                .map(|n| n.to_string())
                .unwrap_or_else(|| UNAVAILABLE.to_string()),
        );
        cells.insert(
            "reviewers".to_string(),
            wave["reviewers"]
                .as_i64()
                .map(|n| n.to_string())
                .unwrap_or_else(|| UNAVAILABLE.to_string()),
        );
        for &metric in ROW_METRICS {
            let val = wave["metrics"][metric]["value"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(UNAVAILABLE)
                .to_string();
            cells.insert(metric.to_string(), val);
        }
        out.insert(k, cells);
    }
    out
}

// ---------------------------------------------------------------------------- read-only SQLite + helpers

fn now_iso_seconds() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
}

fn round_half_even_f64(x: f64) -> i64 {
    let fl = x.floor();
    let frac = x - fl;
    if frac < 0.5 {
        fl as i64
    } else if frac > 0.5 {
        (fl as i64) + 1
    } else {
        let base = fl as i64;
        if base % 2 == 0 {
            base
        } else {
            base + 1
        }
    }
}

fn db_time(value: f64) -> String {
    let whole_secs = value.floor();
    let frac_secs = value - whole_secs;
    let mut secs = whole_secs as i64;
    let mut micros = round_half_even_f64(frac_secs * 1_000_000.0);
    if micros >= 1_000_000 {
        secs += 1;
        micros -= 1_000_000;
    } else if micros < 0 {
        secs -= 1;
        micros += 1_000_000;
    }
    let dt = DateTime::<Utc>::from_timestamp(secs, (micros as u32) * 1000)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"));
    dt.format("%Y-%m-%dT%H:%M:%S.%6f+00:00").to_string()
}

fn percent_encode_uri_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn ro_connect(db_path: &Path) -> rusqlite::Result<Connection> {
    let resolved = fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    let path_str = resolved.to_string_lossy();
    let wal = PathBuf::from(format!("{path_str}-wal"));
    let shm = PathBuf::from(format!("{path_str}-shm"));
    let query = if wal.exists() && shm.exists() {
        "mode=ro"
    } else {
        "mode=ro&immutable=1"
    };
    let uri = format!("file:{}?{query}", percent_encode_uri_path(&path_str));
    let conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn sql_opt_string(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Null => None,
        ValueRef::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
    }
}

fn sql_f64(v: ValueRef<'_>) -> Result<f64, rusqlite::Error> {
    match v {
        ValueRef::Real(f) => Ok(f),
        ValueRef::Integer(i) => Ok(i as f64),
        ValueRef::Text(b) => std::str::from_utf8(b)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(0, "created_at".into(), v.data_type())
            }),
        other => Err(rusqlite::Error::InvalidColumnType(
            0,
            "created_at".into(),
            other.data_type(),
        )),
    }
}

fn parse_json_obj(raw: Option<&str>) -> Map<String, Value> {
    let Some(s) = raw else {
        return Map::new();
    };
    if s.is_empty() {
        return Map::new();
    }
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn valid_sha(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| sha_re().is_match(s))
        .map(ToString::to_string)
}

fn valid_sha_str(value: Option<&str>) -> Option<String> {
    value
        .filter(|s| sha_re().is_match(s))
        .map(ToString::to_string)
}

fn valid_id(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| id_re().is_match(s))
        .map(ToString::to_string)
}

fn valid_id_str(value: Option<&str>) -> Option<String> {
    value
        .filter(|s| id_re().is_match(s))
        .map(ToString::to_string)
}

fn file_sha(path_text: &str) -> Result<String, EventsError> {
    let bytes = fs::read(path_text)
        .map_err(|err| EventsError::Usage(format!("{path_text} is unreadable: {err}")))?;
    Ok(sha256_hex_bytes(&bytes))
}

fn record_events(log: Option<&Path>, events: &[Map<String, Value>]) -> Result<i32, EventsError> {
    let results = append_events(&log_path(log), events)?;
    let mut had_conflict = false;
    for (event_id, status) in &results {
        println!("{status} {event_id}");
        if *status == "conflict" {
            had_conflict = true;
        }
    }
    if had_conflict {
        eprintln!(
            "events: an event_id was re-used with a different body; the report will mark the observations it touches contested"
        );
        return Ok(EXIT_INCOMPLETE);
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------- subcommands

struct EmitArgs {
    kind: String,
    run: String,
    epoch: i64,
    clock: String,
    task: Option<String>,
    dispatch: Option<String>,
    producer: String,
    basis: String,
    observed_at: Option<String>,
    source_ref: String,
    source_sha256: Option<String>,
    source_file: Option<String>,
    event_id: Option<String>,
    data: Option<String>,
}

fn cmd_emit(log: Option<&Path>, args: &EmitArgs) -> Result<i32, EventsError> {
    let data = match &args.data {
        Some(raw) if !raw.is_empty() => serde_json::from_str::<Value>(raw)
            .map_err(|err| EventsError::Usage(format!("--data is not JSON: {err}")))?,
        _ => Value::Object(Map::new()),
    };
    let digest = match &args.source_file {
        Some(sf) if !sf.is_empty() => Some(file_sha(sf)?),
        _ => args.source_sha256.clone(),
    };
    let observed = args.observed_at.clone().unwrap_or_else(now_iso_seconds);
    let event = build_event(&BuildEventParams {
        kind: &args.kind,
        run: &args.run,
        epoch: args.epoch,
        producer: &args.producer,
        clock: &args.clock,
        observed_at: &observed,
        basis: &args.basis,
        source_ref: &args.source_ref,
        source_sha256: digest.as_deref(),
        task: args.task.as_deref(),
        dispatch: args.dispatch.as_deref(),
        data: Some(data),
        event_id: args.event_id.as_deref(),
    })
    .map_err(EventsError::Usage)?;
    record_events(log, &[event])
}

struct IngestDbArgs {
    db: String,
    run: String,
    epoch: i64,
    clock: String,
}

struct DispatchRow {
    dispatch_id: String,
    task_id: String,
    terminal_handle: String,
    state: String,
    agent: Option<String>,
    created_at: f64,
    updated_at: f64,
    head_sha: Option<String>,
    has_intent_id: bool,
    intent_id: Option<String>,
    monitor_started_at_some: bool,
    gate_closed_at_some: bool,
}

fn launch_proof(row: &DispatchRow) -> &'static str {
    if !row.has_intent_id || row.intent_id.as_deref().unwrap_or("").is_empty() {
        return "ungated";
    }
    if row.monitor_started_at_some || row.state == "completed" {
        return "launched";
    }
    if row.gate_closed_at_some {
        "never"
    } else {
        "unresolved"
    }
}

struct StateMessage {
    id: String,
    sender: String,
    attrs_json: Option<String>,
    created_at: f64,
}

fn cmd_ingest_state(log: Option<&Path>, args: &IngestDbArgs) -> Result<i32, EventsError> {
    let db = Path::new(&args.db);
    if !db.is_file() {
        return Err(EventsError::Usage(format!(
            "--db {} is not a file",
            db.display()
        )));
    }
    let db_err = |err: rusqlite::Error| {
        EventsError::FailClosed(format!(
            "{} is not a readable local-state DB: {err}",
            db.display()
        ))
    };
    let conn = ro_connect(db).map_err(db_err)?;

    let rows: Vec<DispatchRow> = {
        let mut stmt = conn
            .prepare("SELECT * FROM dispatches WHERE run_id = ? ORDER BY created_at, dispatch_id")
            .map_err(db_err)?;
        let cols: HashMap<String, usize> = stmt
            .column_names()
            .iter()
            .enumerate()
            .map(|(i, n)| ((*n).to_string(), i))
            .collect();
        let idx = |name: &str| -> Result<usize, rusqlite::Error> {
            cols.get(name)
                .copied()
                .ok_or_else(|| rusqlite::Error::InvalidColumnName(name.to_string()))
        };
        let i_did = idx("dispatch_id").map_err(db_err)?;
        let i_task = idx("task_id").map_err(db_err)?;
        let i_handle = idx("terminal_handle").map_err(db_err)?;
        let i_state = idx("state").map_err(db_err)?;
        let i_agent = cols.get("agent").copied();
        let i_created = idx("created_at").map_err(db_err)?;
        let i_updated = idx("updated_at").map_err(db_err)?;
        let i_head = cols.get("head_sha").copied();
        let i_intent = cols.get("intent_id").copied();
        let i_mon = cols.get("monitor_started_at").copied();
        let i_gate = cols.get("gate_closed_at").copied();

        let mut out = Vec::new();
        let mut qrows = stmt.query([args.run.as_str()]).map_err(db_err)?;
        while let Some(r) = qrows.next().map_err(db_err)? {
            out.push(DispatchRow {
                dispatch_id: sql_opt_string(r.get_ref(i_did).map_err(db_err)?).unwrap_or_default(),
                task_id: sql_opt_string(r.get_ref(i_task).map_err(db_err)?).unwrap_or_default(),
                terminal_handle: sql_opt_string(r.get_ref(i_handle).map_err(db_err)?)
                    .unwrap_or_default(),
                state: sql_opt_string(r.get_ref(i_state).map_err(db_err)?).unwrap_or_default(),
                agent: match i_agent {
                    Some(ci) => sql_opt_string(r.get_ref(ci).map_err(db_err)?),
                    None => None,
                },
                created_at: sql_f64(r.get_ref(i_created).map_err(db_err)?).map_err(db_err)?,
                updated_at: sql_f64(r.get_ref(i_updated).map_err(db_err)?).map_err(db_err)?,
                head_sha: match i_head {
                    Some(ci) => sql_opt_string(r.get_ref(ci).map_err(db_err)?),
                    None => None,
                },
                has_intent_id: i_intent.is_some(),
                intent_id: match i_intent {
                    Some(ci) => sql_opt_string(r.get_ref(ci).map_err(db_err)?),
                    None => None,
                },
                monitor_started_at_some: match i_mon {
                    Some(ci) => !matches!(r.get_ref(ci).map_err(db_err)?, ValueRef::Null),
                    None => false,
                },
                gate_closed_at_some: match i_gate {
                    Some(ci) => !matches!(r.get_ref(ci).map_err(db_err)?, ValueRef::Null),
                    None => false,
                },
            });
        }
        out
    };

    let mail: Vec<StateMessage> = {
        let mut stmt = conn
            .prepare(
                "SELECT id, sender, attrs_json, created_at FROM messages WHERE run_id = ? AND msg_type = 'worker_done' ORDER BY created_at, id",
            )
            .map_err(db_err)?;
        let mut out = Vec::new();
        let mut qrows = stmt.query([args.run.as_str()]).map_err(db_err)?;
        while let Some(r) = qrows.next().map_err(db_err)? {
            out.push(StateMessage {
                id: sql_opt_string(r.get_ref(0).map_err(db_err)?).unwrap_or_default(),
                sender: sql_opt_string(r.get_ref(1).map_err(db_err)?).unwrap_or_default(),
                attrs_json: sql_opt_string(r.get_ref(2).map_err(db_err)?),
                created_at: sql_f64(r.get_ref(3).map_err(db_err)?).map_err(db_err)?,
            });
        }
        out
    };

    let escalations: Vec<StateMessage> = {
        let mut stmt = conn
            .prepare(
                "SELECT id, attrs_json, created_at FROM messages WHERE run_id = ? AND msg_type = 'escalation' ORDER BY created_at, id",
            )
            .map_err(db_err)?;
        let mut out = Vec::new();
        let mut qrows = stmt.query([args.run.as_str()]).map_err(db_err)?;
        while let Some(r) = qrows.next().map_err(db_err)? {
            out.push(StateMessage {
                id: sql_opt_string(r.get_ref(0).map_err(db_err)?).unwrap_or_default(),
                sender: String::new(),
                attrs_json: sql_opt_string(r.get_ref(1).map_err(db_err)?),
                created_at: sql_f64(r.get_ref(2).map_err(db_err)?).map_err(db_err)?,
            });
        }
        out
    };
    drop(conn);

    let mut deaths: HashMap<String, Vec<&StateMessage>> = HashMap::new();
    for msg in &escalations {
        let attrs = parse_json_obj(msg.attrs_json.as_deref());
        if attrs.get("synthetic").and_then(Value::as_str) == Some("worker_died") {
            if let Some(did) = attrs.get("dispatchId").and_then(Value::as_str) {
                deaths.entry(did.to_string()).or_default().push(msg);
            }
        }
    }

    let mut events: Vec<Map<String, Value>> = Vec::new();
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    let mut by_handle: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    let mut never: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut held: Vec<String> = Vec::new();
    let mut earlier: Vec<String> = Vec::new();

    for (i, row) in rows.iter().enumerate() {
        by_handle
            .entry(row.terminal_handle.as_str())
            .or_default()
            .push(i);
        by_id.insert(row.dispatch_id.as_str(), i);
        let proof = launch_proof(row);
        if proof == "never" {
            never.push(row.dispatch_id.clone());
            continue;
        }
        if proof == "unresolved" {
            unresolved.push(row.dispatch_id.clone());
            continue;
        }
        let agent = row
            .agent
            .as_deref()
            .filter(|a| !a.is_empty() && id_re().is_match(a))
            .map(|a| Value::String(a.to_string()))
            .unwrap_or(Value::Null);
        let created = db_time(row.created_at);
        let did = &row.dispatch_id;
        events.push(
            build_event(&BuildEventParams {
                kind: "dispatch.launched",
                run: &args.run,
                epoch: args.epoch,
                producer: "local_state",
                clock: &args.clock,
                observed_at: &created,
                basis: "occurred",
                source_ref: &format!("local-state:dispatches/{did}"),
                source_sha256: None,
                task: Some(&row.task_id),
                dispatch: Some(did),
                data: Some(json!({"agent": agent})),
                event_id: Some(&format!("local-state:dispatch:{did}@{created}")),
            })
            .map_err(EventsError::Usage)?,
        );

        let died: Vec<&StateMessage> = deaths
            .get(did.as_str())
            .map(|list| {
                list.iter()
                    .copied()
                    .filter(|m| m.created_at >= row.created_at)
                    .collect()
            })
            .unwrap_or_default();
        for msg in &died {
            let at = db_time(msg.created_at);
            events.push(
                build_event(&BuildEventParams {
                    kind: "dispatch.died",
                    run: &args.run,
                    epoch: args.epoch,
                    producer: "local_state",
                    clock: &args.clock,
                    observed_at: &at,
                    basis: "occurred",
                    source_ref: &format!("local-state:messages/{}", msg.id),
                    source_sha256: None,
                    task: Some(&row.task_id),
                    dispatch: Some(did),
                    data: None,
                    event_id: Some(&format!("local-state:died:{did}:{}", msg.id)),
                })
                .map_err(EventsError::Usage)?,
            );
        }
        if died.is_empty() && row.state == "died" {
            let at = db_time(row.updated_at);
            events.push(
                build_event(&BuildEventParams {
                    kind: "dispatch.died",
                    run: &args.run,
                    epoch: args.epoch,
                    producer: "local_state",
                    clock: &args.clock,
                    observed_at: &at,
                    basis: "occurred",
                    source_ref: &format!("local-state:dispatches/{did}"),
                    source_sha256: None,
                    task: Some(&row.task_id),
                    dispatch: Some(did),
                    data: None,
                    event_id: Some(&format!("local-state:died:{did}@{at}")),
                })
                .map_err(EventsError::Usage)?,
            );
        }
    }

    let unresolved_set: HashSet<&str> = unresolved.iter().map(String::as_str).collect();
    for msg in &mail {
        let attrs = parse_json_obj(msg.attrs_json.as_deref());
        let unbound = attrs.get("dispatchUnbound") == Some(&Value::Bool(true));
        let attr_did = attrs.get("dispatchId").and_then(Value::as_str);
        let mut matched = if unbound {
            None
        } else {
            attr_did.and_then(|d| by_id.get(d).copied())
        };
        if matched.is_none() {
            matched = by_id.get(msg.sender.as_str()).copied();
        }
        if matched.is_none() {
            if let Some(handles) = by_handle.get(msg.sender.as_str()) {
                if handles.len() == 1 {
                    matched = by_id.get(rows[handles[0]].dispatch_id.as_str()).copied();
                }
            }
        }
        let Some(row_idx) = matched else {
            skipped.push(msg.id.clone());
            continue;
        };
        let row = &rows[row_idx];
        if unbound {
            earlier.push(msg.id.clone());
            continue;
        }
        let named = ["task-id", "task_id", "taskId"]
            .into_iter()
            .find_map(|k| attrs.get(k).and_then(Value::as_str));
        let stale = match named {
            Some(n) => n != row.task_id,
            None => msg.created_at < row.created_at,
        };
        if stale {
            earlier.push(msg.id.clone());
            continue;
        }
        if unresolved_set.contains(row.dispatch_id.as_str()) {
            held.push(msg.id.clone());
            continue;
        }
        let mut heads = vec![
            valid_sha(attrs.get("headSha")),
            valid_sha(attrs.get("head_sha")),
        ];
        let mut event_id = format!("local-state:message:{}", msg.id);
        let from_row = !heads.iter().any(Option::is_some);
        if from_row {
            if !TERMINAL_DISPATCH_STATES.contains(&row.state.as_str()) {
                deferred.push(msg.id.clone());
                continue;
            }
            heads.push(valid_sha_str(row.head_sha.as_deref()));
        }
        let head = heads.into_iter().flatten().next();
        if from_row {
            event_id = bound_id(&event_id, head.as_deref());
        }
        let at = db_time(msg.created_at);
        events.push(
            build_event(&BuildEventParams {
                kind: "task.done",
                run: &args.run,
                epoch: args.epoch,
                producer: "local_state",
                clock: &args.clock,
                observed_at: &at,
                basis: "occurred",
                source_ref: &format!("local-state:messages/{}", msg.id),
                source_sha256: None,
                task: Some(&row.task_id),
                dispatch: Some(&row.dispatch_id),
                data: Some(json!({"head_sha": head})),
                event_id: Some(&event_id),
            })
            .map_err(EventsError::Usage)?,
        );
    }

    if !skipped.is_empty() {
        eprintln!(
            "events: {} worker_done message(s) name no single dispatch of run {} and were not recorded: {}",
            skipped.len(),
            args.run,
            py_list_str(&skipped)
        );
    }
    if !never.is_empty() {
        eprintln!(
            "events: {} dispatch row(s) never launched — the launch gate closed before any monitor claimed it (#597) — and are not recorded: {}",
            never.len(),
            py_list_str(&never)
        );
    }
    if !unresolved.is_empty() {
        eprintln!(
            "events: {} dispatch row(s) have no monitor claim and an open launch gate; each is deferred until the store shows whether it ran: {}",
            unresolved.len(),
            py_list_str(&unresolved)
        );
    }
    if !earlier.is_empty() {
        eprintln!(
            "events: {} worker_done message(s) name another task, or are older than the dispatch row they name — sent by an earlier holder of a re-recorded dispatch id, or before the provider recorded the dispatch — and were not attributed: {}",
            earlier.len(),
            py_list_str(&earlier)
        );
    }
    if !held.is_empty() {
        eprintln!(
            "events: {} worker_done message(s) name a dispatch whose launch is unresolved; each is deferred with it: {}",
            held.len(),
            py_list_str(&held)
        );
    }
    if !deferred.is_empty() {
        eprintln!(
            "events: {} worker_done message(s) name no head and the store has not written their dispatch's yet; each is deferred until its dispatch exits: {}",
            deferred.len(),
            py_list_str(&deferred)
        );
    }
    if events.is_empty() {
        let suffix = if !never.is_empty()
            || !unresolved.is_empty()
            || !held.is_empty()
            || !deferred.is_empty()
            || !earlier.is_empty()
        {
            " yet"
        } else {
            ": the DB holds no dispatch or worker_done for it"
        };
        eprintln!("events: nothing to record for run {}{suffix}", args.run);
        return Ok(EXIT_INCOMPLETE);
    }
    record_events(log, &events)
}

struct MqRow {
    id: i64,
    repo: String,
    base: String,
    entry_id: String,
    kind: String,
    body_json: Option<String>,
    created_at: f64,
    unit: Option<String>,
    reviewed_sha: Option<String>,
    reviewed_tree: Option<String>,
    accepted_head: Option<String>,
    merge_sha: Option<String>,
}

fn cmd_ingest_merge_queue(log: Option<&Path>, args: &IngestDbArgs) -> Result<i32, EventsError> {
    let db = Path::new(&args.db);
    if !db.is_file() {
        return Err(EventsError::Usage(format!(
            "--db {} is not a file",
            db.display()
        )));
    }
    let db_err = |err: rusqlite::Error| {
        EventsError::FailClosed(format!(
            "{} is not a readable merge-queue DB: {err}",
            db.display()
        ))
    };
    let conn = ro_connect(db).map_err(db_err)?;
    let rows: Vec<MqRow> = {
        let mut stmt = conn
            .prepare(
                "SELECT r.id, r.repo, r.base, r.entry_id, r.kind, r.epoch, r.holder, \
                 r.body_json, r.created_at, e.run_id, e.unit, e.reviewed_sha, \
                 e.reviewed_tree, e.accepted_head, e.merge_sha, e.merged_tree, e.state \
                 FROM mq_receipts r JOIN mq_entries e ON r.entry_id = e.entry_id \
                 WHERE e.run_id = ? ORDER BY r.created_at, r.id",
            )
            .map_err(db_err)?;
        let mut out = Vec::new();
        let mut qrows = stmt.query([args.run.as_str()]).map_err(db_err)?;
        while let Some(r) = qrows.next().map_err(db_err)? {
            out.push(MqRow {
                id: r.get(0).map_err(db_err)?,
                repo: sql_opt_string(r.get_ref(1).map_err(db_err)?).unwrap_or_default(),
                base: sql_opt_string(r.get_ref(2).map_err(db_err)?).unwrap_or_default(),
                entry_id: sql_opt_string(r.get_ref(3).map_err(db_err)?).unwrap_or_default(),
                kind: sql_opt_string(r.get_ref(4).map_err(db_err)?).unwrap_or_default(),
                body_json: sql_opt_string(r.get_ref(7).map_err(db_err)?),
                created_at: sql_f64(r.get_ref(8).map_err(db_err)?).map_err(db_err)?,
                unit: sql_opt_string(r.get_ref(10).map_err(db_err)?),
                reviewed_sha: sql_opt_string(r.get_ref(11).map_err(db_err)?),
                reviewed_tree: sql_opt_string(r.get_ref(12).map_err(db_err)?),
                accepted_head: sql_opt_string(r.get_ref(13).map_err(db_err)?),
                merge_sha: sql_opt_string(r.get_ref(14).map_err(db_err)?),
            });
        }
        out
    };
    drop(conn);

    let mut events: Vec<Map<String, Value>> = Vec::new();
    let mut skipped: Vec<i64> = Vec::new();

    let mut add = |row: &MqRow,
                   body: &Map<String, Value>,
                   task: &str,
                   at: &str,
                   body_sha: &str,
                   kind: &str,
                   data: Value|
     -> Result<(), EventsError> {
        let key = py_canonical_json(&json!({
            "repo": row.repo,
            "base": row.base,
            "entry_id": row.entry_id,
            "receipt_kind": row.kind,
            "created_at": at,
            "body": Value::Object(body.clone()),
            "kind": kind,
            "task": task,
            "data": data,
        }));
        let digest = sha256_hex(&key);
        events.push(
            build_event(&BuildEventParams {
                kind,
                run: &args.run,
                epoch: args.epoch,
                producer: "merge_queue",
                clock: &args.clock,
                observed_at: at,
                basis: "occurred",
                source_ref: &format!("merge-queue:mq_receipts/{}", row.id),
                source_sha256: Some(body_sha),
                task: Some(task),
                dispatch: None,
                data: Some(data),
                event_id: Some(&format!("merge-queue:{kind}:{}", &digest[..32])),
            })
            .map_err(EventsError::Usage)?,
        );
        Ok(())
    };

    for row in &rows {
        let Some(task) = valid_id_str(row.unit.as_deref()) else {
            skipped.push(row.id);
            continue;
        };
        let body_raw = match row.body_json.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => "{}",
        };
        let body = parse_json_obj(Some(body_raw));
        let at = db_time(row.created_at);
        let body_sha = sha256_hex_bytes(body_raw.as_bytes());
        let rkind = row.kind.as_str();
        if matches!(rkind, "acknowledged" | "merged" | "closed")
            || (rkind == "reconciled"
                && body.get("resolution").and_then(Value::as_str) == Some("merged"))
        {
            let head = valid_sha(body.get("acceptedHead"))
                .or_else(|| valid_sha(body.get("headSha")))
                .or_else(|| valid_sha(body.get("head_sha")))
                .or_else(|| valid_sha_str(row.accepted_head.as_deref()))
                .or_else(|| valid_sha_str(row.reviewed_sha.as_deref()))
                .or_else(|| valid_sha(body.get("mergeSha")))
                .or_else(|| valid_sha_str(row.merge_sha.as_deref()));
            let Some(head) = head else {
                skipped.push(row.id);
                continue;
            };
            let wtree = valid_sha(body.get("reviewedTree"))
                .or_else(|| valid_sha_str(row.reviewed_tree.as_deref()));
            add(
                row,
                &body,
                &task,
                &at,
                &body_sha,
                "unit.closed",
                json!({"head_sha": head, "head_wtree": wtree}),
            )?;
        } else if rkind == "returned_to_review" {
            add(row, &body, &task, &at, &body_sha, "unit.suspect", json!({}))?;
            let reviewed = valid_sha(body.get("reviewedSha"))
                .or_else(|| valid_sha_str(row.reviewed_sha.as_deref()));
            let moved = valid_sha(body.get("head"));
            if let (Some(rev), Some(mov)) = (reviewed, moved) {
                if mov != rev {
                    add(
                        row,
                        &body,
                        &task,
                        &at,
                        &body_sha,
                        "review.voided",
                        json!({"reviewed_sha": rev, "head_sha": mov}),
                    )?;
                }
            }
        } else if rkind == "failed"
            || (rkind == "reconciled"
                && body.get("resolution").and_then(Value::as_str) == Some("failed"))
        {
            add(row, &body, &task, &at, &body_sha, "unit.suspect", json!({}))?;
        } else if rkind == "resolved" {
            match body.get("action").and_then(Value::as_str) {
                Some("drop") => {
                    let park_class = valid_id(body.get("park_class"))
                        .unwrap_or_else(|| "merge-dropped".to_string());
                    let head = valid_sha_str(row.accepted_head.as_deref())
                        .or_else(|| valid_sha_str(row.reviewed_sha.as_deref()));
                    add(
                        row,
                        &body,
                        &task,
                        &at,
                        &body_sha,
                        "unit.parked",
                        json!({"park_class": park_class, "head_sha": head}),
                    )?;
                }
                Some("bounce") => {
                    add(row, &body, &task, &at, &body_sha, "unit.suspect", json!({}))?;
                }
                _ => {}
            }
        } else if rkind == "parked" {
            let park_class =
                valid_id(body.get("park_class")).unwrap_or_else(|| "merge-parked".to_string());
            let head = valid_sha(body.get("headSha"))
                .or_else(|| valid_sha(body.get("head_sha")))
                .or_else(|| valid_sha_str(row.accepted_head.as_deref()))
                .or_else(|| valid_sha_str(row.reviewed_sha.as_deref()));
            add(
                row,
                &body,
                &task,
                &at,
                &body_sha,
                "unit.parked",
                json!({"park_class": park_class, "head_sha": head}),
            )?;
        }
    }

    if !skipped.is_empty() {
        eprintln!(
            "events: {} merge-queue receipt(s) could not bind a valid unit or head SHA and were skipped: {}",
            skipped.len(),
            py_list_i64(&skipped)
        );
    }
    if events.is_empty() {
        eprintln!(
            "events: nothing to record from merge-queue DB for run {}",
            args.run
        );
        return Ok(EXIT_INCOMPLETE);
    }
    record_events(log, &events)
}

struct LaunchIntentRow {
    intent_id: String,
    task_id: Option<String>,
    dispatch_id: Option<String>,
    outcome: Option<String>,
    receipt_json: Option<String>,
    created_at: f64,
    updated_at: f64,
    dispatch_agent: Option<String>,
    dispatch_monitor_started_at_some: bool,
}

fn cmd_ingest_launch(log: Option<&Path>, args: &IngestDbArgs) -> Result<i32, EventsError> {
    let db = Path::new(&args.db);
    if !db.is_file() {
        return Err(EventsError::Usage(format!(
            "--db {} is not a file",
            db.display()
        )));
    }
    let db_err = |err: rusqlite::Error| {
        EventsError::FailClosed(format!(
            "{} is not a readable launch-intents DB: {err}",
            db.display()
        ))
    };
    let conn = ro_connect(db).map_err(db_err)?;
    let has_dispatches: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'dispatches'",
            [],
            |_| Ok(true),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(db_err)?
        .is_some();

    let sql = if has_dispatches {
        "SELECT l.intent_id, l.task_id, l.run_id, l.dispatch_id, l.phase, \
         l.outcome, l.receipt_json, l.created_at, l.updated_at, \
         d.agent AS dispatch_agent, \
         d.monitor_started_at AS dispatch_monitor_started_at \
         FROM launch_intents l \
         LEFT JOIN dispatches d ON l.dispatch_id = d.dispatch_id \
         WHERE l.run_id = ? ORDER BY l.created_at, l.intent_id"
    } else {
        "SELECT intent_id, task_id, run_id, dispatch_id, phase, outcome, \
         receipt_json, created_at, updated_at, \
         NULL AS dispatch_agent, NULL AS dispatch_monitor_started_at \
         FROM launch_intents WHERE run_id = ? ORDER BY created_at, intent_id"
    };

    let rows: Vec<LaunchIntentRow> = {
        let mut stmt = conn.prepare(sql).map_err(db_err)?;
        let mut out = Vec::new();
        let mut qrows = stmt.query([args.run.as_str()]).map_err(db_err)?;
        while let Some(r) = qrows.next().map_err(db_err)? {
            out.push(LaunchIntentRow {
                intent_id: sql_opt_string(r.get_ref(0).map_err(db_err)?).unwrap_or_default(),
                task_id: sql_opt_string(r.get_ref(1).map_err(db_err)?),
                dispatch_id: sql_opt_string(r.get_ref(3).map_err(db_err)?),
                outcome: sql_opt_string(r.get_ref(5).map_err(db_err)?),
                receipt_json: sql_opt_string(r.get_ref(6).map_err(db_err)?),
                created_at: sql_f64(r.get_ref(7).map_err(db_err)?).map_err(db_err)?,
                updated_at: sql_f64(r.get_ref(8).map_err(db_err)?).map_err(db_err)?,
                dispatch_agent: sql_opt_string(r.get_ref(9).map_err(db_err)?),
                dispatch_monitor_started_at_some: !matches!(
                    r.get_ref(10).map_err(db_err)?,
                    ValueRef::Null
                ),
            });
        }
        out
    };
    drop(conn);

    let mut events: Vec<Map<String, Value>> = Vec::new();
    let mut never: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for row in &rows {
        let iid = &row.intent_id;
        match row.outcome.as_deref() {
            None | Some("unknown") => {
                unresolved.push(iid.clone());
                continue;
            }
            Some("failed") if !row.dispatch_monitor_started_at_some => {
                never.push(iid.clone());
                continue;
            }
            Some("completed" | "failed") => {}
            _ => {
                skipped.push(iid.clone());
                continue;
            }
        }
        let (Some(task), Some(did)) = (
            valid_id_str(row.task_id.as_deref()),
            valid_id_str(row.dispatch_id.as_deref()),
        ) else {
            skipped.push(iid.clone());
            continue;
        };
        let receipt_raw = row.receipt_json.as_deref().unwrap_or("");
        let receipt = parse_json_obj(Some(receipt_raw));
        let agent = valid_id_str(row.dispatch_agent.as_deref())
            .or_else(|| {
                receipt
                    .get("effective")
                    .and_then(Value::as_object)
                    .and_then(|o| valid_id(o.get("agent")))
            })
            .or_else(|| {
                receipt
                    .get("launchEffective")
                    .and_then(Value::as_object)
                    .and_then(|o| valid_id(o.get("agent")))
            })
            .or_else(|| valid_id(receipt.get("agent")));
        let created = db_time(row.created_at);
        let source_ref = format!("local-state:launch_intents/{iid}");
        let source_sha = if receipt_raw.is_empty() {
            None
        } else {
            Some(sha256_hex_bytes(receipt_raw.as_bytes()))
        };
        let key = py_canonical_json(&json!({
            "intent_id": iid,
            "task_id": task,
            "dispatch_id": did,
            "created_at": created,
            "kind": "dispatch.launched",
            "agent": agent,
        }));
        let key_sha = sha256_hex(&key);
        events.push(
            build_event(&BuildEventParams {
                kind: "dispatch.launched",
                run: &args.run,
                epoch: args.epoch,
                producer: "launch_intent",
                clock: &args.clock,
                observed_at: &created,
                basis: "occurred",
                source_ref: &source_ref,
                source_sha256: source_sha.as_deref(),
                task: Some(&task),
                dispatch: Some(&did),
                data: Some(json!({"agent": agent})),
                event_id: Some(&format!(
                    "launch-intent:dispatch.launched:{}",
                    &key_sha[..32]
                )),
            })
            .map_err(EventsError::Usage)?,
        );

        let disp_after = receipt
            .get("dispatch")
            .and_then(Value::as_object)
            .and_then(|d| d.get("after"))
            .and_then(Value::as_str);
        if receipt.get("kind").and_then(Value::as_str) == Some("launch_recovery")
            && receipt.get("resolution").and_then(Value::as_str) == Some("exited")
            && disp_after == Some("died")
        {
            let died_at = match receipt.get("reconciledAt") {
                Some(Value::Number(n)) => n
                    .as_f64()
                    .map(db_time)
                    .unwrap_or_else(|| db_time(row.updated_at)),
                _ => db_time(row.updated_at),
            };
            let dkey = py_canonical_json(&json!({
                "intent_id": iid,
                "task_id": task,
                "dispatch_id": did,
                "died_at": died_at,
                "kind": "dispatch.died",
            }));
            let dkey_sha = sha256_hex(&dkey);
            events.push(
                build_event(&BuildEventParams {
                    kind: "dispatch.died",
                    run: &args.run,
                    epoch: args.epoch,
                    producer: "launch_intent",
                    clock: &args.clock,
                    observed_at: &died_at,
                    basis: "occurred",
                    source_ref: &source_ref,
                    source_sha256: source_sha.as_deref(),
                    task: Some(&task),
                    dispatch: Some(&did),
                    data: Some(json!({})),
                    event_id: Some(&format!("launch-intent:dispatch.died:{}", &dkey_sha[..32])),
                })
                .map_err(EventsError::Usage)?,
            );
        }
    }

    if !never.is_empty() {
        eprintln!(
            "events: {} launch intent(s) failed before any worker ran and are not recorded: {}",
            never.len(),
            py_list_str(&never)
        );
    }
    if !unresolved.is_empty() {
        eprintln!(
            "events: {} launch intent(s) are still open or unknown and are deferred until settled: {}",
            unresolved.len(),
            py_list_str(&unresolved)
        );
    }
    if !skipped.is_empty() {
        eprintln!(
            "events: {} launch intent(s) were skipped (unrecognized outcome or invalid task/dispatch id): {}",
            skipped.len(),
            py_list_str(&skipped)
        );
    }
    if events.is_empty() {
        let suffix = if !never.is_empty() || !unresolved.is_empty() {
            " yet"
        } else {
            ": the DB holds no settled launch intent for it"
        };
        eprintln!(
            "events: nothing to record from launch_intents for run {}{suffix}",
            args.run
        );
        return Ok(EXIT_INCOMPLETE);
    }
    record_events(log, &events)
}

struct IngestTranscriptArgs {
    transcript: String,
    manifest: Option<String>,
    run: String,
    epoch: i64,
    clock: String,
    task: String,
}

fn cmd_ingest_transcript(
    log: Option<&Path>,
    args: &IngestTranscriptArgs,
) -> Result<i32, EventsError> {
    let path = Path::new(&args.transcript);
    let raw = fs::read(path).map_err(|err| {
        EventsError::Usage(format!(
            "--transcript {} is not a readable verify.py transcript: {err}",
            path.display()
        ))
    })?;
    let text = std::str::from_utf8(&raw).map_err(|err| {
        EventsError::Usage(format!(
            "--transcript {} is not a readable verify.py transcript: {err}",
            path.display()
        ))
    })?;
    let doc: Value = serde_json::from_str(text).map_err(|err| {
        EventsError::Usage(format!(
            "--transcript {} is not a readable verify.py transcript: {err}",
            path.display()
        ))
    })?;
    let record_val = match &doc {
        Value::Object(m) if m.contains_key("sig_b64") => m.get("record"),
        _ => Some(&doc),
    };
    let Some(Value::Object(record)) = record_val else {
        return Err(EventsError::Usage(format!(
            "--transcript {} carries no verify.py verdict (exit, timestamp)",
            path.display()
        )));
    };
    let Some(exit_code) = record.get("exit").and_then(Value::as_i64) else {
        return Err(EventsError::Usage(format!(
            "--transcript {} carries no verify.py verdict (exit, timestamp)",
            path.display()
        )));
    };
    let Some(timestamp) = record.get("timestamp").and_then(Value::as_str) else {
        return Err(EventsError::Usage(format!(
            "--transcript {} carries no verify.py verdict (exit, timestamp)",
            path.display()
        )));
    };

    let mut head: Option<String> = None;
    let manifest = args
        .manifest
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            record
                .get("manifest")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        });
    if let (Some(mpath), Some(expected_sha)) = (
        manifest,
        record.get("manifest_sha256").and_then(Value::as_str),
    ) {
        let mbytes = fs::read(mpath).ok();
        match mbytes {
            Some(bytes) if sha256_hex_bytes(&bytes) == expected_sha => {
                if let Ok(mtext) = std::str::from_utf8(&bytes) {
                    if let Ok(Value::Object(mobj)) = serde_json::from_str::<Value>(mtext) {
                        head = valid_sha(mobj.get("head_sha"));
                    }
                }
            }
            _ => {
                eprintln!(
                    "events: {mpath} is absent or not the bytes the verdict judged; the verdict is recorded without a head"
                );
            }
        }
    }

    let digest = sha256_hex_bytes(&raw);
    let event = build_event(&BuildEventParams {
        kind: "verify.verdict",
        run: &args.run,
        epoch: args.epoch,
        producer: "verify.py",
        clock: &args.clock,
        observed_at: timestamp,
        basis: "occurred",
        source_ref: &args.transcript,
        source_sha256: Some(&digest),
        task: Some(&args.task),
        dispatch: None,
        data: Some(json!({"exit": exit_code, "head_sha": head})),
        event_id: Some(&bound_id(
            &format!("verify-transcript:{digest}"),
            head.as_deref(),
        )),
    })
    .map_err(EventsError::Usage)?;
    record_events(log, &[event])
}

struct IngestUsageArgs {
    stream: String,
    run: String,
    epoch: i64,
    clock: String,
    task: Option<String>,
    dispatch: Option<String>,
    observed_at: Option<String>,
}

fn cmd_ingest_usage(log: Option<&Path>, args: &IngestUsageArgs) -> Result<i32, EventsError> {
    let path = Path::new(&args.stream);
    let raw = fs::read(path).map_err(|err| {
        EventsError::Usage(format!("--stream {} is unreadable: {err}", path.display()))
    })?;
    let mut model: Option<String> = None;
    let mut events: Vec<Map<String, Value>> = Vec::new();
    let mut end: isize = -1;
    for (idx, chunk) in raw.split(|&b| b == b'\n').enumerate() {
        let lineno = idx + 1;
        end += 1 + chunk.len() as isize;
        let line_text = String::from_utf8_lossy(chunk);
        let Some(Value::Object(obj)) = parse_json_lenient_nonfinite(&line_text) else {
            continue;
        };
        if obj.get("type").and_then(Value::as_str) == Some("system")
            && obj.get("subtype").and_then(Value::as_str) == Some("init")
        {
            if let Some(m) = valid_id(obj.get("model")) {
                model = Some(m);
            }
        }
        if obj.get("type").and_then(Value::as_str) != Some("result") {
            continue;
        }
        let usage = obj.get("usage").and_then(Value::as_object);
        let mut data = Map::new();
        data.insert(
            "model".to_string(),
            model.clone().map(Value::String).unwrap_or(Value::Null),
        );
        for &field in TOKEN_FIELDS {
            let val = usage
                .and_then(|u| u.get(field))
                .and_then(Value::as_i64)
                .filter(|&v| v >= 0)
                .map(|v| Value::Number(Number::from(v)))
                .unwrap_or(Value::Null);
            data.insert(field.to_string(), val);
        }
        let cost = parse_money_json(obj.get("total_cost_usd"));
        data.insert(
            "cost_usd".to_string(),
            cost.map(Value::String).unwrap_or(Value::Null),
        );
        let mut absent: Vec<&str> = Vec::new();
        for &f in ["model"].iter().chain(USAGE_FIELDS.iter()) {
            if data.get(f).is_none_or(Value::is_null) {
                absent.push(f);
            }
        }
        let digest = sha256_hex_bytes(&raw[..(end as usize)]);
        let suffix = if absent.is_empty() {
            String::new()
        } else {
            format!("; not reported: {}", absent.join(", "))
        };
        let prov = format!(
            "claude stream-json result line {lineno}, lines 1-{lineno} sha256:{}{suffix}",
            &digest[..16]
        );
        data.insert("provenance".to_string(), Value::String(prov));
        let observed = args.observed_at.clone().unwrap_or_else(now_iso_seconds);
        events.push(
            build_event(&BuildEventParams {
                kind: "model.usage",
                run: &args.run,
                epoch: args.epoch,
                producer: "claude-stream-json",
                clock: &args.clock,
                observed_at: &observed,
                basis: "observed",
                source_ref: &args.stream,
                source_sha256: Some(&digest),
                task: args.task.as_deref(),
                dispatch: args.dispatch.as_deref(),
                data: Some(Value::Object(data)),
                event_id: Some(&format!("claude-stream:{digest}:{lineno}")),
            })
            .map_err(EventsError::Usage)?,
        );
    }

    if events.is_empty() {
        eprintln!(
            "events: {} carries no result line; usage for this dispatch stays unobserved",
            path.display()
        );
        return Ok(EXIT_INCOMPLETE);
    }
    record_events(log, &events)
}

fn check_anchored(
    log: Option<&Path>,
    events: &[LogEvent],
    head: &str,
    expect_head: Option<&str>,
    expect_ancestor: Option<&str>,
) -> Result<(), EventsError> {
    if let Some(why) = check_anchor(events, head, expect_head, expect_ancestor) {
        return Err(EventsError::FailClosed(format!(
            "TAMPER at {} — {why} (#312)",
            log_path(log).display()
        )));
    }
    Ok(())
}

struct AnchorArgs {
    expect_head: Option<String>,
    expect_ancestor: Option<String>,
}

fn cmd_verify(log: Option<&Path>, anchors: &AnchorArgs) -> Result<i32, EventsError> {
    let path = log_path(log);
    let (events, _file_sha, head) = read_log(&path)?;
    check_anchored(
        log,
        &events,
        &head,
        anchors.expect_head.as_deref(),
        anchors.expect_ancestor.as_deref(),
    )?;
    let has_anchor = anchors
        .expect_head
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        || anchors
            .expect_ancestor
            .as_deref()
            .is_some_and(|s| !s.is_empty());
    let note = if has_anchor {
        ""
    } else {
        " (UNANCHORED: edits are caught, a wholesale rewrite is not — keep this head off the writer and pass it back as --expect-ancestor or --expect-head)"
    };
    let head_shown = if head.is_empty() { "(empty)" } else { &head };
    println!(
        "events: chain intact, {} event(s) in {} — head {head_shown}{note}",
        events.len(),
        path.display()
    );
    Ok(EXIT_OK)
}

struct ReportArgs {
    run: Option<String>,
    json: bool,
    anchors: AnchorArgs,
}

fn cmd_report(log: Option<&Path>, args: &ReportArgs) -> Result<i32, EventsError> {
    let path = log_path(log);
    let (events, file_sha, head) = read_log(&path)?;
    check_anchored(
        log,
        &events,
        &head,
        args.anchors.expect_head.as_deref(),
        args.anchors.expect_ancestor.as_deref(),
    )?;
    let report = derive(&events, args.run.as_deref(), &file_sha, &head)?;
    if args.json {
        println!("{}", py_pretty_json(&report));
    } else {
        print!("{}", render_markdown(&report));
    }
    if report["complete"].as_bool() == Some(true) {
        Ok(EXIT_OK)
    } else {
        Ok(EXIT_INCOMPLETE)
    }
}

struct CheckArgs {
    run_report: String,
    run: Option<String>,
    anchors: AnchorArgs,
}

fn cmd_check(log: Option<&Path>, args: &CheckArgs) -> Result<i32, EventsError> {
    let path = log_path(log);
    let (events, file_sha, head) = read_log(&path)?;
    check_anchored(
        log,
        &events,
        &head,
        args.anchors.expect_head.as_deref(),
        args.anchors.expect_ancestor.as_deref(),
    )?;
    let report = derive(&events, args.run.as_deref(), &file_sha, &head)?;
    let text = fs::read_to_string(&args.run_report).map_err(|err| {
        EventsError::Usage(format!(
            "--run-report {} is unreadable: {err}",
            args.run_report
        ))
    })?;
    let derived = derived_cells(&report);
    let mut errors: Vec<String> = Vec::new();
    let mut claimed: BTreeMap<String, Vec<BTreeMap<String, String>>> = BTreeMap::new();
    if derived.is_empty() {
        errors.push(format!(
            "the record derives no WIP-curve row for run {}: no wave.open or wave.close was admitted, so there is nothing to check against",
            report["run"].as_str().unwrap_or("")
        ));
    }
    for row in wip_rows(&text) {
        if !row.doubled.is_empty() {
            errors.push(format!(
                "row {} carries {} more than once",
                py_repr_str(&row.raw),
                py_list_str(&row.doubled)
            ));
        }
        let wave_key = row.cells.get("wave").cloned().unwrap_or_default();
        claimed.entry(wave_key).or_default().push(row.cells);
    }
    for (wave, rows) in &claimed {
        if rows.len() > 1 {
            errors.push(format!("wave {wave}: {} rows", rows.len()));
        }
        let is_derived_wave = !wave.is_empty()
            && wave.bytes().all(|b| b.is_ascii_digit())
            && wave
                .parse::<i64>()
                .ok()
                .is_some_and(|n| derived.contains_key(&n));
        if !is_derived_wave {
            errors.push(format!(
                "wave {wave}: the report carries a row for a wave the record never opened or closed"
            ));
        }
    }
    for (&k, cells) in &derived {
        let Some(rows) = claimed.get(&k.to_string()) else {
            errors.push(format!(
                "wave {k}: the record derives a row the report does not carry"
            ));
            continue;
        };
        for &key in WIP_ROW_KEYS {
            let want = cells[key].as_str();
            let got = rows[0].get(key).map(String::as_str);
            if want == UNAVAILABLE {
                errors.push(format!(
                    "wave {k} {key}: the record cannot derive it, yet the report claims {}",
                    py_repr_opt_str(got)
                ));
            } else if got != Some(want) {
                errors.push(format!(
                    "wave {k} {key}: the report says {}, the record derives {}",
                    py_repr_opt_str(got),
                    py_repr_str(want)
                ));
            }
        }
    }
    for line in &errors {
        eprintln!("events: MISMATCH {line}");
    }
    if !errors.is_empty() {
        return Ok(EXIT_INCOMPLETE);
    }
    let head_shown = if head.is_empty() { "(empty)" } else { &head };
    println!(
        "events: {} WIP-curve row(s) in {} match the record (sha256 {file_sha}, head {head_shown})",
        derived.len(),
        args.run_report
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------- raw CLI parser

enum ParsedCli {
    Help(String),
    Emit(Option<PathBuf>, EmitArgs),
    IngestState(Option<PathBuf>, IngestDbArgs),
    IngestLaunch(Option<PathBuf>, IngestDbArgs),
    IngestMergeQueue(Option<PathBuf>, IngestDbArgs),
    IngestTranscript(Option<PathBuf>, IngestTranscriptArgs),
    IngestUsage(Option<PathBuf>, IngestUsageArgs),
    Verify(Option<PathBuf>, AnchorArgs),
    Report(Option<PathBuf>, ReportArgs),
    Check(Option<PathBuf>, CheckArgs),
}

fn top_help() -> String {
    format!(
        "usage: events.py [-h] [--log LOG]\n                 {{emit,ingest-state,ingest-launch,ingest-merge-queue,ingest-transcript,ingest-usage,verify,report,check}} ...\n\n\
         Append-only lifecycle event record and the WIP-curve rows derived from it.\n\n\
         options:\n  -h, --help  show this help message and exit\n  --log LOG   record path (default ${PRIMARY_LOG_ENV}, ${LOG_ENV} or {DEFAULT_LOG})\n\n\
         exit 0 ok / 1 incomplete or mismatch / 2 usage / 3 fail-closed\n"
    )
}

fn sub_help(cmd: &str) -> String {
    format!("usage: events.py {cmd} [-h] ...\n")
}

fn split_opt(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((k, v)) if k.starts_with("--") => (k, Some(v)),
        _ => (arg, None),
    }
}

fn take_val(
    tokens: &[String],
    idx: &mut usize,
    flag: &str,
    inline: Option<&str>,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v.to_string());
    }
    if *idx + 1 >= tokens.len() {
        return Err(format!("argument {flag}: expected one argument"));
    }
    let next = &tokens[*idx + 1];
    if next == "-h" || next.starts_with("--") {
        return Err(format!("argument {flag}: expected one argument"));
    }
    *idx += 1;
    Ok(next.clone())
}

fn parse_epoch_val(raw: &str) -> Result<i64, String> {
    raw.trim()
        .parse::<i64>()
        .map_err(|_| format!("argument --epoch: invalid int value: {}", py_repr_str(raw)))
}

fn parse_ts_opt(raw: &str) -> Result<String, String> {
    valid_ts(raw)?;
    Ok(raw.to_string())
}

fn require_arg<T>(val: Option<T>, flag: &str) -> Result<T, String> {
    val.ok_or_else(|| format!("the following arguments are required: {flag}"))
}

fn parse_raw_args(raw: &[OsString]) -> Result<ParsedCli, String> {
    let tokens: Vec<String> = raw
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let mut i = 0usize;
    let mut log: Option<PathBuf> = None;

    while i < tokens.len() {
        let tok = &tokens[i];
        if tok == "-h" || tok == "--help" {
            return Ok(ParsedCli::Help(top_help()));
        }
        let (flag, inline) = split_opt(tok);
        if flag == "--log" {
            let val = take_val(&tokens, &mut i, "--log", inline)?;
            log = Some(PathBuf::from(val));
            i += 1;
            continue;
        }
        if tok.starts_with('-') {
            return Err(format!("unrecognized arguments: {tok}"));
        }
        break;
    }

    if i >= tokens.len() {
        return Err("the following arguments are required: command".to_string());
    }
    let cmd = tokens[i].as_str();
    let rest = &tokens[i + 1..];

    match cmd {
        "emit" => {
            let mut kind = None;
            let mut run = None;
            let mut epoch = None;
            let mut clock = None;
            let mut task = None;
            let mut dispatch = None;
            let mut producer = "coordinator".to_string();
            let mut basis = "observed".to_string();
            let mut observed_at = None;
            let mut source_ref = None;
            let mut source_sha256 = None;
            let mut source_file = None;
            let mut event_id = None;
            let mut data = None;

            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help("emit")));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--kind" => {
                        let v = take_val(rest, &mut j, flag, inline)?;
                        if !KINDS.contains(&v.as_str()) {
                            return Err(format!(
                                "argument --kind: invalid choice: {} (choose from {})",
                                py_repr_str(&v),
                                py_list_str_refs(KINDS)
                            ));
                        }
                        kind = Some(v);
                    }
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--epoch" => {
                        epoch = Some(parse_epoch_val(&take_val(rest, &mut j, flag, inline)?)?)
                    }
                    "--clock" => clock = Some(take_val(rest, &mut j, flag, inline)?),
                    "--task" => task = Some(take_val(rest, &mut j, flag, inline)?),
                    "--dispatch" => dispatch = Some(take_val(rest, &mut j, flag, inline)?),
                    "--producer" => producer = take_val(rest, &mut j, flag, inline)?,
                    "--basis" => {
                        let v = take_val(rest, &mut j, flag, inline)?;
                        if !BASES.contains(&v.as_str()) {
                            return Err(format!(
                                "argument --basis: invalid choice: {} (choose from {})",
                                py_repr_str(&v),
                                py_list_str_refs(BASES)
                            ));
                        }
                        basis = v;
                    }
                    "--observed-at" => {
                        observed_at = Some(parse_ts_opt(&take_val(rest, &mut j, flag, inline)?)?);
                    }
                    "--source-ref" => source_ref = Some(take_val(rest, &mut j, flag, inline)?),
                    "--source-sha256" => {
                        source_sha256 = Some(take_val(rest, &mut j, flag, inline)?)
                    }
                    "--source-file" => source_file = Some(take_val(rest, &mut j, flag, inline)?),
                    "--event-id" => event_id = Some(take_val(rest, &mut j, flag, inline)?),
                    "--data" => data = Some(take_val(rest, &mut j, flag, inline)?),
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::Emit(
                log,
                EmitArgs {
                    kind: require_arg(kind, "--kind")?,
                    run: require_arg(run, "--run")?,
                    epoch: require_arg(epoch, "--epoch")?,
                    clock: require_arg(clock, "--clock")?,
                    task,
                    dispatch,
                    producer,
                    basis,
                    observed_at,
                    source_ref: require_arg(source_ref, "--source-ref")?,
                    source_sha256,
                    source_file,
                    event_id,
                    data,
                },
            ))
        }
        "ingest-state" | "ingest-launch" | "ingest-merge-queue" => {
            let mut db = None;
            let mut run = None;
            let mut epoch = None;
            let mut clock = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--db" => db = Some(take_val(rest, &mut j, flag, inline)?),
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--epoch" => {
                        epoch = Some(parse_epoch_val(&take_val(rest, &mut j, flag, inline)?)?)
                    }
                    "--clock" => clock = Some(take_val(rest, &mut j, flag, inline)?),
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            let db_args = IngestDbArgs {
                db: require_arg(db, "--db")?,
                run: require_arg(run, "--run")?,
                epoch: require_arg(epoch, "--epoch")?,
                clock: require_arg(clock, "--clock")?,
            };
            match cmd {
                "ingest-state" => Ok(ParsedCli::IngestState(log, db_args)),
                "ingest-launch" => Ok(ParsedCli::IngestLaunch(log, db_args)),
                _ => Ok(ParsedCli::IngestMergeQueue(log, db_args)),
            }
        }
        "ingest-transcript" => {
            let mut transcript = None;
            let mut manifest = None;
            let mut run = None;
            let mut epoch = None;
            let mut clock = None;
            let mut task = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--transcript" => transcript = Some(take_val(rest, &mut j, flag, inline)?),
                    "--manifest" => manifest = Some(take_val(rest, &mut j, flag, inline)?),
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--epoch" => {
                        epoch = Some(parse_epoch_val(&take_val(rest, &mut j, flag, inline)?)?)
                    }
                    "--clock" => clock = Some(take_val(rest, &mut j, flag, inline)?),
                    "--task" => task = Some(take_val(rest, &mut j, flag, inline)?),
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::IngestTranscript(
                log,
                IngestTranscriptArgs {
                    transcript: require_arg(transcript, "--transcript")?,
                    manifest,
                    run: require_arg(run, "--run")?,
                    epoch: require_arg(epoch, "--epoch")?,
                    clock: require_arg(clock, "--clock")?,
                    task: require_arg(task, "--task")?,
                },
            ))
        }
        "ingest-usage" => {
            let mut stream = None;
            let mut run = None;
            let mut epoch = None;
            let mut clock = None;
            let mut task = None;
            let mut dispatch = None;
            let mut observed_at = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--stream" => stream = Some(take_val(rest, &mut j, flag, inline)?),
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--epoch" => {
                        epoch = Some(parse_epoch_val(&take_val(rest, &mut j, flag, inline)?)?)
                    }
                    "--clock" => clock = Some(take_val(rest, &mut j, flag, inline)?),
                    "--task" => task = Some(take_val(rest, &mut j, flag, inline)?),
                    "--dispatch" => dispatch = Some(take_val(rest, &mut j, flag, inline)?),
                    "--observed-at" => {
                        observed_at = Some(parse_ts_opt(&take_val(rest, &mut j, flag, inline)?)?);
                    }
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::IngestUsage(
                log,
                IngestUsageArgs {
                    stream: require_arg(stream, "--stream")?,
                    run: require_arg(run, "--run")?,
                    epoch: require_arg(epoch, "--epoch")?,
                    clock: require_arg(clock, "--clock")?,
                    task,
                    dispatch,
                    observed_at,
                },
            ))
        }
        "verify" => {
            let mut expect_head = None;
            let mut expect_ancestor = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--expect-head" => expect_head = Some(take_val(rest, &mut j, flag, inline)?),
                    "--expect-ancestor" => {
                        expect_ancestor = Some(take_val(rest, &mut j, flag, inline)?);
                    }
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::Verify(
                log,
                AnchorArgs {
                    expect_head,
                    expect_ancestor,
                },
            ))
        }
        "report" => {
            let mut run = None;
            let mut json_flag = false;
            let mut expect_head = None;
            let mut expect_ancestor = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--json" if inline.is_none() => json_flag = true,
                    "--expect-head" => expect_head = Some(take_val(rest, &mut j, flag, inline)?),
                    "--expect-ancestor" => {
                        expect_ancestor = Some(take_val(rest, &mut j, flag, inline)?);
                    }
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::Report(
                log,
                ReportArgs {
                    run,
                    json: json_flag,
                    anchors: AnchorArgs {
                        expect_head,
                        expect_ancestor,
                    },
                },
            ))
        }
        "check" => {
            let mut run_report = None;
            let mut run = None;
            let mut expect_head = None;
            let mut expect_ancestor = None;
            let mut j = 0usize;
            while j < rest.len() {
                if rest[j] == "-h" || rest[j] == "--help" {
                    return Ok(ParsedCli::Help(sub_help(cmd)));
                }
                let (flag, inline) = split_opt(&rest[j]);
                match flag {
                    "--run-report" => run_report = Some(take_val(rest, &mut j, flag, inline)?),
                    "--run" => run = Some(take_val(rest, &mut j, flag, inline)?),
                    "--expect-head" => expect_head = Some(take_val(rest, &mut j, flag, inline)?),
                    "--expect-ancestor" => {
                        expect_ancestor = Some(take_val(rest, &mut j, flag, inline)?);
                    }
                    other => return Err(format!("unrecognized arguments: {other}")),
                }
                j += 1;
            }
            Ok(ParsedCli::Check(
                log,
                CheckArgs {
                    run_report: require_arg(run_report, "--run-report")?,
                    run,
                    anchors: AnchorArgs {
                        expect_head,
                        expect_ancestor,
                    },
                },
            ))
        }
        other => Err(format!(
            "argument command: invalid choice: {}",
            py_repr_str(other)
        )),
    }
}

pub fn run_raw(args: &[OsString]) -> i32 {
    let parsed = match parse_raw_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("events.py: error: {msg}");
            return EXIT_USAGE;
        }
    };
    let result = match parsed {
        ParsedCli::Help(text) => {
            print!("{text}");
            return EXIT_OK;
        }
        ParsedCli::Emit(log, a) => cmd_emit(log.as_deref(), &a),
        ParsedCli::IngestState(log, a) => cmd_ingest_state(log.as_deref(), &a),
        ParsedCli::IngestLaunch(log, a) => cmd_ingest_launch(log.as_deref(), &a),
        ParsedCli::IngestMergeQueue(log, a) => cmd_ingest_merge_queue(log.as_deref(), &a),
        ParsedCli::IngestTranscript(log, a) => cmd_ingest_transcript(log.as_deref(), &a),
        ParsedCli::IngestUsage(log, a) => cmd_ingest_usage(log.as_deref(), &a),
        ParsedCli::Verify(log, a) => cmd_verify(log.as_deref(), &a),
        ParsedCli::Report(log, a) => cmd_report(log.as_deref(), &a),
        ParsedCli::Check(log, a) => cmd_check(log.as_deref(), &a),
    };
    match result {
        Ok(code) => code,
        Err(EventsError::Usage(err)) => {
            eprintln!("events: usage: {err}");
            EXIT_USAGE
        }
        Err(EventsError::FailClosed(err)) => {
            eprintln!("events: FAIL-CLOSED: {err}");
            EXIT_FAIL_CLOSED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_escapes_non_ascii_and_sorts_keys() {
        let v = json!({
            "z": "em\u{2014}dash",
            "a": "\u{1F600}",
            "m": [1, true, null, "line\nbreak"]
        });
        assert_eq!(
            py_canonical_json(&v),
            r#"{"a":"\ud83d\ude00","m":[1,true,null,"line\nbreak"],"z":"em\u2014dash"}"#
        );
    }

    #[test]
    fn decimal_round_half_even_ties_to_even() {
        assert_eq!(format_decimal_half_even(Frac::new(1, 200), 2), "0.00");
        assert_eq!(format_decimal_half_even(Frac::new(3, 200), 2), "0.02");
        assert_eq!(format_decimal_half_even(Frac::new(5, 200), 2), "0.02");
        assert_eq!(format_decimal_half_even(Frac::new(7, 200), 2), "0.04");
        assert_eq!(format_decimal_half_even(Frac::new(7200, 6300), 2), "1.14");
        assert_eq!(format_decimal_half_even(Frac::new(3600, 4200), 2), "0.86");
        assert_eq!(format_decimal_half_even(Frac::new(-300, 1), 2), "-300.00");
    }

    #[test]
    fn money_decimal_preserves_python_scale() {
        let mut total = MoneyDecimal::zero();
        for s in ["0.50", "0.25", "0.10", "0.15"] {
            total.add_assign(&MoneyDecimal::parse(s));
        }
        assert_eq!(total.format_fixed(), "1.00");

        let mut mixed = MoneyDecimal::zero();
        mixed.add_assign(&MoneyDecimal::parse("0.5"));
        mixed.add_assign(&MoneyDecimal::parse("0.25"));
        assert_eq!(mixed.format_fixed(), "0.75");
        assert_eq!(MoneyDecimal::zero().format_fixed(), "0");
    }

    #[test]
    fn sanitize_nonfinite_preserves_string_literals() {
        let raw = r#"{"msg":"NaN Infinity -Infinity","a":NaN,"b":Infinity,"c":-Infinity,"n":1}"#;
        let parsed = parse_json_lenient_nonfinite(raw).expect("parses");
        assert_eq!(parsed["msg"], "NaN Infinity -Infinity");
        assert!(parsed["a"].is_null());
        assert!(parsed["b"].is_null());
        assert!(parsed["c"].is_null());
        assert_eq!(parsed["n"], 1);
    }

    #[test]
    fn redaction_covers_keys_and_url_credentials() {
        let tok = format!("{}{}{}", "gh", "p_", "Z".repeat(36));
        let val = json!({
            tok.clone(): "https://alice:supersecretpass@example.com/hook"
        });
        let redacted = redact(val);
        assert_eq!(
            redacted["[REDACTED:github-token]"],
            "[REDACTED:url-credential]@example.com/hook"
        );
    }
}
