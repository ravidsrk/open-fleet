//! POSIX shell lexing, glob matching, path/home helpers, command wrapper peeling,
//! and diff/patch target extraction ported faithfully from `runtime/scripts/deny-hook.sh`.

use crate::types::QNL;
use regex::Regex;
use std::sync::OnceLock;

const SQ: char = '\'';
const DQ: char = '"';

pub(crate) const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "hush",
];

pub(crate) const AWKS: &[&str] = &["awk", "gawk", "mawk", "nawk"];

const BUSYBOX_EXTRA_APPLETS: &[&str] = &[
    "sed", "tar", "unzip", "cpio", "rm", "rmdir", "cp", "mv", "dd", "tee", "wget", "vi", "ln",
    "install", "chmod", "chown", "chgrp", "env", "xargs", "timeout", "nohup", "nice", "chroot",
    "setsid", "truncate", "shred", "unlink", "sort", "patch", "find", "cat", "head", "tail", "tac",
    "uniq",
];

const SEND_VERBS: &[&str] = &[
    "create",
    "merge",
    "comment",
    "review",
    "close",
    "reopen",
    "edit",
    "delete",
    "upload",
    "ready",
    "pin",
    "unpin",
    "lock",
    "unlock",
    "transfer",
    "revert",
    "update-branch",
    "develop",
    "delete-asset",
];

const GH_OPERAND_FLAGS: &[&str] = &["-R", "--repo", "--hostname"];

const GH_API_VAL_LONG: &[&str] = &[
    "--header",
    "--jq",
    "--template",
    "--preview",
    "--cache",
    "--hostname",
    "--repo",
];
const GH_API_VAL_SHORT: &str = "HqtpR";

const WRAPPERS: &[&str] = &["command", "builtin"];
const ENV_OPERAND_FLAGS: &[&str] = &["-u", "--unset", "-a", "--argv0", "-C", "--chdir"];
const NICE_OPERAND_FLAGS: &[&str] = &["-n", "--adjustment"];
const TIME_OPERAND_FLAGS: &[&str] = &["-o", "--output", "-f", "--format"];
const NOHUP_OPERAND_FLAGS: &[&str] = &[];
const SUDO_OPERAND_FLAGS: &[&str] = &["-u", "-U", "-g", "-h", "-p", "-C", "-T", "-R", "-t"];

const RECEIPT_LAUNCHERS: &[&str] = &["timeout", "stdbuf", "ionice", "chrt", "taskset", "doas"];
const KEYWORDS: &[&str] = &["if", "then", "elif", "else", "do", "while", "until"];

const GIT_GLOBAL_ARG: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeelMode {
    Basic,
    Extended,
    Receipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum RedirFd {
    Num(String),
    Amp,
}

impl RedirFd {
    pub(crate) fn from_digits(digits: &str) -> Self {
        let trimmed = digits.trim_start_matches('0');
        Self::Num(if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        })
    }

    pub(crate) fn is_zero(&self) -> bool {
        matches!(self, Self::Num(s) if s == "0")
    }

    pub(crate) fn is_stdout_or_amp(&self) -> bool {
        matches!(self, Self::Amp) || matches!(self, Self::Num(s) if s == "1")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShellToken {
    Redirect {
        op: String,
        fd: RedirFd,
        raw: String,
    },
    Word {
        val: String,
        raw: String,
    },
}

#[inline]
pub(crate) fn is_blank(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

#[inline]
fn py_isspace(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\x1c'..='\x1f')
}

#[inline]
fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[inline]
pub(crate) fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(is_ident_char)
}

#[inline]
pub(crate) fn is_env_assign(w: &str) -> bool {
    match w.find('=') {
        Some(idx) => is_ident(&w[..idx]),
        None => false,
    }
}

#[inline]
pub(crate) fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

pub(crate) fn is_wrapper_word(head: &str) -> bool {
    WRAPPERS.contains(&head)
}

pub(crate) fn is_receipt_launcher(head: &str) -> bool {
    RECEIPT_LAUNCHERS.contains(&head)
}

pub(crate) fn is_keyword(head: &str) -> bool {
    KEYWORDS.contains(&head)
}

pub(crate) fn wrapper_operands(head: &str) -> Option<&'static [&'static str]> {
    match head {
        "env" => Some(ENV_OPERAND_FLAGS),
        "nice" => Some(NICE_OPERAND_FLAGS),
        "time" => Some(TIME_OPERAND_FLAGS),
        "nohup" => Some(NOHUP_OPERAND_FLAGS),
        _ => None,
    }
}

pub(crate) fn launcher_spec(head: &str) -> Option<(&'static str, &'static [&'static str], usize)> {
    match head {
        "timeout" => Some(("sk", &["--signal", "--kill-after"], 1)),
        "stdbuf" => Some(("ioe", &["--input", "--output", "--error"], 0)),
        "ionice" => Some((
            "cnpPu",
            &["--class", "--classdata", "--pid", "--pgid", "--uid"],
            0,
        )),
        "chrt" => Some((
            "TPD",
            &["--sched-runtime", "--sched-period", "--sched-deadline"],
            1,
        )),
        "taskset" => Some(("", &[], 1)),
        "doas" => Some(("auC", &[], 0)),
        "setsid" => Some(("", &[], 0)),
        "exec" => Some(("a", &[], 0)),
        "xargs" => Some((
            "adEILnPsJRS",
            &[
                "--arg-file",
                "--delimiter",
                "--max-args",
                "--max-procs",
                "--max-chars",
                "--process-slot-var",
            ],
            0,
        )),
        "chroot" => Some(("", &["--userspec", "--groups"], 1)),
        "unshare" => Some((
            "SGRw",
            &[
                "--setuid",
                "--setgid",
                "--root",
                "--wd",
                "--propagation",
                "--setgroups",
                "--map-user",
                "--map-group",
                "--map-users",
                "--map-groups",
            ],
            0,
        )),
        "nsenter" => Some(("tSG", &["--target", "--setuid", "--setgid"], 0)),
        "strace" => Some((
            "eopsuEabIOPSXU",
            &[
                "--output",
                "--attach",
                "--string-limit",
                "--user",
                "--env",
                "--columns",
                "--trace-path",
                "--summary-sort-by",
                "--signal",
                "--status",
                "--trace",
                "--abbrev",
                "--verbose",
                "--raw",
                "--read",
                "--write",
                "--inject",
                "--fault",
                "--quiet",
                "--decode-fds",
            ],
            0,
        )),
        _ => None,
    }
}

pub(crate) fn is_write_redirect_op(op: &str) -> bool {
    matches!(op, ">" | ">>" | ">|" | ">&" | "&>" | "&>>" | "<>")
}

fn is_busybox_applet(word: &str) -> bool {
    AWKS.contains(&word) || SHELLS.contains(&word) || BUSYBOX_EXTRA_APPLETS.contains(&word)
}

pub(crate) fn is_awk(head: &str) -> bool {
    if AWKS.contains(&head) || matches!(head, "goawk" | "original-awk") {
        return true;
    }
    head.ends_with("awk")
        && head[..head.len() - 3]
            .bytes()
            .all(|b| b.is_ascii_lowercase())
}

pub(crate) fn canon_interp(head: &str) -> &str {
    for (prefix, key) in [
        ("python", "python"),
        ("luajit", "luajit"),
        ("lua", "lua"),
        ("ruby", "ruby"),
        ("php", "php"),
        ("perl", "perl"),
    ] {
        if let Some(rest) = head.strip_prefix(prefix) {
            if rest.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                return key;
            }
        }
    }
    head
}

pub(crate) fn peel_shell(ws: &[String]) -> Vec<String> {
    if let Some(first) = ws.first() {
        let (head, rest) = peel_busybox(basename(first), &ws[1..]);
        if SHELLS.contains(&head.as_str()) && rest.len() + 1 < ws.len() {
            let mut out = Vec::with_capacity(1 + rest.len());
            out.push(head);
            out.extend(rest);
            return out;
        }
    }
    ws.to_vec()
}

pub(crate) fn operands(rest: &[String], opt_arg: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut end = false;
    while i < rest.len() {
        let w = &rest[i];
        if !end && w == "--" {
            end = true;
        } else if !end && w.starts_with('-') && w != "-" {
            if opt_arg.contains(&w.as_str()) {
                i += 1;
            }
        } else {
            out.push(w.clone());
        }
        i += 1;
    }
    out
}

/// Exact POSIX `shlex.split(s)` parity (`posix=True`, `comments=False`).
pub fn shlex_split(s: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut out = Vec::new();

    while i < n {
        // Skip shlex whitespace (' ', '\t', '\r', '\n').
        while i < n && matches!(chars[i], ' ' | '\t' | '\r' | '\n') {
            i += 1;
        }
        if i >= n {
            break;
        }

        let mut token = String::new();
        let mut state: Option<char> = None; // None = unquoted word, Some('\'') or Some('"')

        while i < n {
            let ch = chars[i];
            match state {
                None => {
                    if matches!(ch, ' ' | '\t' | '\r' | '\n') {
                        break;
                    } else if ch == SQ || ch == DQ {
                        state = Some(ch);
                        i += 1;
                    } else if ch == '\\' {
                        if i + 1 >= n {
                            return Err("No escaped character".to_string());
                        }
                        token.push(chars[i + 1]);
                        i += 2;
                    } else {
                        token.push(ch);
                        i += 1;
                    }
                }
                Some(SQ) => {
                    if ch == SQ {
                        state = None;
                    } else {
                        token.push(ch);
                    }
                    i += 1;
                }
                Some(DQ) => {
                    if ch == DQ {
                        state = None;
                        i += 1;
                    } else if ch == '\\' {
                        if i + 1 >= n {
                            return Err("No escaped character".to_string());
                        }
                        let nxt = chars[i + 1];
                        if nxt == DQ || nxt == '\\' {
                            token.push(nxt);
                        } else {
                            token.push('\\');
                            token.push(nxt);
                        }
                        i += 2;
                    } else {
                        token.push(ch);
                        i += 1;
                    }
                }
                Some(_) => {
                    token.push(ch);
                    i += 1;
                }
            }
        }

        if state.is_some() {
            return Err("No closing quotation".to_string());
        }
        out.push(token);
    }

    Ok(out)
}

/// Exact Python `shlex.quote(s)` parity.
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let all_safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
            )
    });
    if all_safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Exact Python `shlex.join(words)` parity.
pub fn shlex_join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| shlex_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone)]
enum GlobAtom {
    Literal(char),
    Any,
    Star,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

fn compile_fnmatch(pat: &str) -> Vec<GlobAtom> {
    let chars: Vec<char> = pat.chars().collect();
    let n = chars.len();
    let mut atoms = Vec::new();
    let mut i = 0;

    while i < n {
        match chars[i] {
            '*' => {
                if !matches!(atoms.last(), Some(GlobAtom::Star)) {
                    atoms.push(GlobAtom::Star);
                }
                i += 1;
            }
            '?' => {
                atoms.push(GlobAtom::Any);
                i += 1;
            }
            '[' => {
                let mut j = i + 1;
                let negated = if j < n && chars[j] == '!' {
                    j += 1;
                    true
                } else {
                    false
                };
                let mut k = j;
                if k < n && chars[k] == ']' {
                    k += 1;
                }
                while k < n && chars[k] != ']' {
                    k += 1;
                }
                if k >= n {
                    atoms.push(GlobAtom::Literal('['));
                    i += 1;
                } else {
                    let mut ranges = Vec::new();
                    let mut p = j;
                    while p < k {
                        if p + 2 < k && chars[p + 1] == '-' {
                            ranges.push((chars[p], chars[p + 2]));
                            p += 3;
                        } else {
                            ranges.push((chars[p], chars[p]));
                            p += 1;
                        }
                    }
                    atoms.push(GlobAtom::Class { negated, ranges });
                    i = k + 1;
                }
            }
            ch => {
                atoms.push(GlobAtom::Literal(ch));
                i += 1;
            }
        }
    }

    atoms
}

/// Exact Python `fnmatch.fnmatchcase(name, pat)` parity (`*`, `?`, `[seq]`, `[!seq]`).
pub fn fnmatchcase(name: &str, pat: &str) -> bool {
    let atoms = compile_fnmatch(pat);
    let chars: Vec<char> = name.chars().collect();
    let m = chars.len();

    let mut dp = vec![false; m + 1];
    dp[0] = true;

    for atom in &atoms {
        let mut next = vec![false; m + 1];
        match atom {
            GlobAtom::Star => {
                let mut seen = false;
                for j in 0..=m {
                    if dp[j] {
                        seen = true;
                    }
                    next[j] = seen;
                }
            }
            GlobAtom::Any => {
                for j in 0..m {
                    if dp[j] {
                        next[j + 1] = true;
                    }
                }
            }
            GlobAtom::Literal(expected) => {
                for j in 0..m {
                    if dp[j] && chars[j] == *expected {
                        next[j + 1] = true;
                    }
                }
            }
            GlobAtom::Class { negated, ranges } => {
                for j in 0..m {
                    if dp[j] {
                        let ch = chars[j];
                        let in_set = ranges.iter().any(|&(lo, hi)| lo <= ch && ch <= hi);
                        if in_set != *negated {
                            next[j + 1] = true;
                        }
                    }
                }
            }
        }
        dp = next;
    }

    dp[m]
}

/// Exact POSIX `os.path.normpath` parity.
pub(crate) fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let initial_slashes = if path.starts_with('/') {
        if path.starts_with("//") && !path.starts_with("///") {
            2
        } else {
            1
        }
    } else {
        0
    };

    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && comps.is_empty())
            || comps.last().copied() == Some("..")
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }

    let mut out = String::new();
    for _ in 0..initial_slashes {
        out.push('/');
    }
    out.push_str(&comps.join("/"));
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

#[cfg(unix)]
fn lookup_pw_dir_by_name(user: &str) -> Option<String> {
    use std::ffi::{CStr, CString};

    let c_user = CString::new(user).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    loop {
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1024 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let pw = unsafe { pwd.assume_init() };
        if pw.pw_dir.is_null() {
            return None;
        }
        let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
        return Some(dir.to_string_lossy().into_owned());
    }
}

#[cfg(not(unix))]
fn lookup_pw_dir_by_name(_user: &str) -> Option<String> {
    None
}

#[cfg(unix)]
fn lookup_current_pw_dir() -> Option<String> {
    use std::ffi::CStr;

    let uid = unsafe { libc::getuid() };
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    loop {
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1024 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let pw = unsafe { pwd.assume_init() };
        if pw.pw_dir.is_null() {
            return None;
        }
        let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
        return Some(dir.to_string_lossy().into_owned());
    }
}

#[cfg(not(unix))]
fn lookup_current_pw_dir() -> Option<String> {
    None
}

pub(crate) fn expanduser(path: &str, home: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let slash_pos = path[1..].find('/').map(|idx| idx + 1).unwrap_or(path.len());
    let user = &path[1..slash_pos];
    let userhome = if user.is_empty() {
        if !home.is_empty() {
            home.to_string()
        } else {
            match lookup_current_pw_dir() {
                Some(dir) => dir,
                None => return path.to_string(),
            }
        }
    } else {
        match lookup_pw_dir_by_name(user) {
            Some(dir) => dir,
            None => return path.to_string(),
        }
    };
    let trimmed = userhome.trim_end_matches('/');
    let joined = format!("{trimmed}{}", &path[slash_pos..]);
    if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    }
}

fn match_home_var_prefix(p: &str) -> Option<&str> {
    if let Some(rest) = p.strip_prefix("$HOME") {
        if rest.is_empty() || rest.starts_with('/') {
            return Some(rest);
        }
    }
    if let Some(rest) = p.strip_prefix("${HOME}") {
        if rest.is_empty() || rest.starts_with('/') {
            return Some(rest);
        }
    }
    None
}

/// Exact port of `_home_path` (`L4227–4239`): unconditional `~`, `~user`, `$HOME`, `${HOME}`.
pub fn home_path(p: &str, home: &str) -> String {
    if p.starts_with('~') {
        return expanduser(p, home);
    }
    if let Some(rest) = match_home_var_prefix(p) {
        let base = if !home.is_empty() {
            home.to_string()
        } else {
            expanduser("~", home)
        };
        return format!("{base}{rest}");
    }
    p.to_string()
}

/// Exact port of `_sh_home_path` (`L4242–4252`): quote-aware `~` / `$HOME` / `${HOME}` expansion.
pub fn sh_home_path(val: &str, rawslice: &str, home: &str) -> String {
    if val.starts_with('~') {
        return if rawslice.starts_with('~') {
            home_path(val, home)
        } else {
            val.to_string()
        };
    }
    if match_home_var_prefix(val).is_some() {
        let inner = rawslice.strip_prefix(DQ).unwrap_or(rawslice);
        return if inner.starts_with('$') {
            home_path(val, home)
        } else {
            val.to_string()
        };
    }
    val.to_string()
}

/// Exact port of `_unquote_c_path` (`L1727–1750`).
pub fn unquote_c_path(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() >= 2 && trimmed.starts_with(DQ) && trimmed.ends_with(DQ) {
        let inner: Vec<char> = trimmed[1..trimmed.len() - 1].chars().collect();
        let n = inner.len();
        let mut raw: Vec<u8> = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let ch = inner[i];
            if ch == '\\' && i + 1 < n {
                let nxt = inner[i + 1];
                let mapped = match nxt {
                    'a' => Some(7u8),
                    'b' => Some(8),
                    'f' => Some(12),
                    'n' => Some(10),
                    'r' => Some(13),
                    't' => Some(9),
                    'v' => Some(11),
                    '\\' => Some(92),
                    '"' => Some(34),
                    _ => None,
                };
                if let Some(b) = mapped {
                    raw.push(b);
                    i += 2;
                } else if ('0'..='7').contains(&nxt)
                    && i + 3 < n
                    && ('0'..='7').contains(&inner[i + 2])
                    && ('0'..='7').contains(&inner[i + 3])
                {
                    let oct = ((nxt as u32 - '0' as u32) << 6)
                        | ((inner[i + 2] as u32 - '0' as u32) << 3)
                        | (inner[i + 3] as u32 - '0' as u32);
                    raw.push((oct & 0xFF) as u8);
                    i += 4;
                } else {
                    let mut buf = [0u8; 4];
                    raw.extend_from_slice(nxt.encode_utf8(&mut buf).as_bytes());
                    i += 2;
                }
            } else {
                let mut buf = [0u8; 4];
                raw.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                i += 1;
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    } else {
        trimmed.to_string()
    }
}

fn split_patch_lines(blob: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = blob.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out.push(&blob[start..i]);
            i += 1;
            start = i;
        } else if bytes[i] == b'\r' {
            out.push(&blob[start..i]);
            i += if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                2
            } else {
                1
            };
            start = i;
        } else {
            i += 1;
        }
    }
    if start < bytes.len() {
        out.push(&blob[start..]);
    }
    out
}

/// Exact port of `patch_targets` (`L1753–1770`).
pub fn patch_targets(blob: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in split_patch_lines(blob) {
        let mut is_diff_hdr = false;
        let captured = if let Some(rest) = line
            .strip_prefix("*** Add File:")
            .or_else(|| line.strip_prefix("*** Update File:"))
            .or_else(|| line.strip_prefix("*** Delete File:"))
            .or_else(|| line.strip_prefix("*** Move to:"))
        {
            let trimmed = rest.trim_start();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        } else if let Some(rest) = line
            .strip_prefix("+++ ")
            .or_else(|| line.strip_prefix("--- "))
        {
            is_diff_hdr = true;
            let end = rest.find(['\t', '\r', '\n']).unwrap_or(rest.len());
            if end > 0 {
                Some(&rest[..end])
            } else {
                None
            }
        } else {
            None
        };

        if let Some(raw_cand) = captured {
            let mut cand = unquote_c_path(raw_cand);
            if is_diff_hdr {
                if let Some(stripped) = cand.strip_prefix("a/").or_else(|| cand.strip_prefix("b/"))
                {
                    cand = stripped.to_string();
                }
            }
            let cand = cand.trim();
            if !cand.is_empty() && cand != "/dev/null" {
                found.push(cand.to_string());
            }
        }
    }
    found
}

/// Exact port of `policy_word` (`L1270–1276`).
pub fn policy_word(w: &str) -> String {
    let word = w.replace(QNL, "\n");
    if word.is_empty() {
        return "\\000".to_string();
    }
    let mut out = String::with_capacity(word.len());
    for ch in word.chars() {
        if py_isspace(ch) || ch == SQ || ch == DQ || ch == '\\' {
            out.push_str(&format!("\\{:03o}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

fn norm_join(sep_chars: &str) -> String {
    let core: String = sep_chars.chars().filter(|&c| c != '\n').collect();
    if core.is_empty() {
        "start".to_string()
    } else if core == "|" || core == "|&" {
        "|".to_string()
    } else if core == ";" {
        ";".to_string()
    } else if core == "&&" {
        "&&".to_string()
    } else {
        "seq".to_string()
    }
}

/// Exact port of `_split` (`L1148–1263`): quote-aware segment splitter returning `(join, seg)`.
pub fn split_segments(cmd: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = cmd.chars().collect();
    let n = chars.len();
    let mut segs: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let mut cur_join = "start".to_string();
    let mut sep_run = String::new();
    let mut i = 0;
    let mut quote: Option<char> = None;
    let mut word_start = true;
    let mut ansi = false;
    let mut dollar = false;

    while i < n {
        let ch = chars[i];
        let was_dollar = dollar;
        dollar = false;

        if ch == '\\' && quote != Some(SQ) && i + 1 < n && chars[i + 1] == '\n' {
            i += 2;
            continue;
        }
        if let Some(q) = quote {
            sep_run.clear();
            cur.push(if ch == '\n' { QNL } else { ch });
            if ch == '\\' && (q == DQ || ansi) && i + 1 < n {
                cur.push(if chars[i + 1] == '\n' {
                    QNL
                } else {
                    chars[i + 1]
                });
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
                ansi = false;
            }
            word_start = false;
            i += 1;
            continue;
        }
        if ch == SQ || ch == DQ {
            quote = Some(ch);
            ansi = ch == SQ && was_dollar;
            sep_run.clear();
            cur.push(ch);
            word_start = false;
            i += 1;
            continue;
        }
        if ch == '\\' && i + 1 < n {
            sep_run.clear();
            cur.push(ch);
            cur.push(chars[i + 1]);
            word_start = false;
            i += 2;
            continue;
        }
        if ch == '#' && word_start {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '<' || ch == '>' || (ch == '&' && i + 1 < n && chars[i + 1] == '>') {
            let mut j = i + 1;
            while j < n && matches!(chars[j], '<' | '>' | '|' | '&') {
                j += 1;
            }
            sep_run.clear();
            for &c in &chars[i..j] {
                cur.push(c);
            }
            word_start = false;
            i = j;
            continue;
        }
        if matches!(ch, ';' | '|' | '&' | '\n') {
            if !cur.is_empty() {
                segs.push((cur_join.clone(), std::mem::take(&mut cur)));
            }
            sep_run.push(ch);
            cur_join = norm_join(&sep_run);
            word_start = true;
            i += 1;
            continue;
        }
        if !is_blank(ch) || !cur.trim().is_empty() {
            sep_run.clear();
        }
        cur.push(ch);
        word_start = is_blank(ch);
        dollar = ch == '$';
        i += 1;
    }

    if !cur.is_empty() {
        segs.push((cur_join, cur));
    }
    segs.into_iter()
        .filter(|(_, seg)| !seg.trim().is_empty())
        .collect()
}

fn match_ifs_expansion(chars: &[char], i: usize) -> Option<usize> {
    let n = chars.len();
    if i >= n || chars[i] != '$' {
        return None;
    }
    if i + 4 <= n && chars[i + 1] == 'I' && chars[i + 2] == 'F' && chars[i + 3] == 'S' {
        if i + 4 == n || !is_ident_char(chars[i + 4]) {
            return Some(i + 4);
        }
        return None;
    }
    if i + 5 <= n
        && chars[i + 1] == '{'
        && chars[i + 2] == 'I'
        && chars[i + 3] == 'F'
        && chars[i + 4] == 'S'
    {
        let k = i + 5;
        if k < n && chars[k] == '}' {
            return Some(k + 1);
        }
        if k < n && !is_ident_char(chars[k]) {
            let mut end = k + 1;
            while end < n && chars[end] != '}' {
                end += 1;
            }
            if end < n {
                return Some(end + 1);
            }
        }
    }
    None
}

fn match_redirect_op(chars: &[char], i: usize, target: bool) -> Option<(usize, String, RedirFd)> {
    const OPS: &[&str] = &[
        "&>>", "&>", ">>", ">|", ">&", "<>", "<<<", "<<-", "<<", "<&", ">", "<",
    ];
    let n = chars.len();
    let mut op_start = i;
    if !target {
        while op_start < n && chars[op_start].is_ascii_digit() {
            op_start += 1;
        }
    }
    for &op in OPS {
        let op_chars: Vec<char> = op.chars().collect();
        if op_start + op_chars.len() <= n && chars[op_start..op_start + op_chars.len()] == op_chars
        {
            let end = op_start + op_chars.len();
            let fd = if op_start > i {
                let digits: String = chars[i..op_start].iter().collect();
                RedirFd::from_digits(&digits)
            } else if op.starts_with('&') {
                RedirFd::Amp
            } else if op.starts_with('>') {
                RedirFd::Num("1".to_string())
            } else {
                RedirFd::Num("0".to_string())
            };
            return Some((end, op.to_string(), fd));
        }
    }
    None
}

fn ansi_c(chars: &[char], mut j: usize) -> Result<(String, usize), String> {
    let n = chars.len();
    let mut out = String::new();
    let mut cut = false;

    while j < n {
        let ch = chars[j];
        if ch == SQ {
            return Ok((out, j + 1));
        }
        let mut val = ch.to_string();
        let mut step = 1usize;

        if ch == '\\' && j + 1 < n {
            let nxt = chars[j + 1];
            step = 2;
            let simple = match nxt {
                'a' => Some("\x07".to_string()),
                'b' => Some("\x08".to_string()),
                'e' | 'E' => Some("\x1b".to_string()),
                'f' => Some("\x0c".to_string()),
                'n' => Some(QNL.to_string()),
                'r' => Some(" ".to_string()),
                't' => Some("\t".to_string()),
                'v' => Some("\x0b".to_string()),
                '\\' => Some("\\".to_string()),
                '\'' => Some("'".to_string()),
                '"' => Some("\"".to_string()),
                '?' => Some("?".to_string()),
                _ => None,
            };
            if let Some(s) = simple {
                val = s;
            } else if ('0'..='7').contains(&nxt) {
                let mut end = j + 1;
                while end < n && end < j + 4 && ('0'..='7').contains(&chars[end]) {
                    end += 1;
                }
                let digits: String = chars[j + 1..end].iter().collect();
                let code = u32::from_str_radix(&digits, 8).unwrap_or(0) & 255;
                val = char::from_u32(code).unwrap_or('?').to_string();
                step = end - j;
            } else if matches!(nxt, 'x' | 'u' | 'U') {
                let max_len = match nxt {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let mut end = j + 2;
                while end < n && end < j + 2 + max_len && chars[end].is_ascii_hexdigit() {
                    end += 1;
                }
                if end > j + 2 {
                    let digits: String = chars[j + 2..end].iter().collect();
                    let code = u32::from_str_radix(&digits, 16).unwrap_or(0x110000);
                    val = char::from_u32(code).unwrap_or('?').to_string();
                    step = end - j;
                } else {
                    val = format!("\\{nxt}");
                }
            } else if nxt == 'c' && j + 2 < n {
                let code = (chars[j + 2] as u32) & 31;
                val = char::from_u32(code).unwrap_or('?').to_string();
                step = 3;
            } else {
                val = format!("\\{nxt}");
            }
        }

        if val == "\0" {
            cut = true;
        }
        if !cut {
            let cleaned = val.replace('\n', &QNL.to_string()).replace('\r', " ");
            out.push_str(&cleaned);
        }
        j += step;
    }

    Err("unclosed ANSI-C quote".to_string())
}

fn unquote_word(text: &str) -> Result<String, String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut quote: Option<char> = None;

    while i < n {
        let ch = chars[i];
        if quote == Some(SQ) {
            if ch == SQ {
                quote = None;
            }
            out.push(ch);
            i += 1;
        } else if quote == Some(DQ) {
            if ch == '\\' && i + 1 < n {
                let nxt = chars[i + 1];
                if nxt == '$' || nxt == '`' {
                    out.push(nxt);
                } else {
                    out.push('\\');
                    out.push(nxt);
                }
                i += 2;
                continue;
            }
            if ch == DQ {
                quote = None;
            }
            out.push(ch);
            i += 1;
        } else if ch == '\\' && i + 1 < n {
            out.push('\\');
            out.push(chars[i + 1]);
            i += 2;
        } else if ch == '$' && i + 1 < n && chars[i + 1] == SQ {
            let (body, next_i) = ansi_c(&chars, i + 2)?;
            out.push(SQ);
            out.push_str(&body.replace(SQ, "'\\''"));
            out.push(SQ);
            i = next_i;
        } else if ch == '$' && i + 1 < n && chars[i + 1] == DQ {
            i += 1;
        } else {
            if ch == SQ || ch == DQ {
                quote = Some(ch);
            }
            out.push(ch);
            i += 1;
        }
    }

    let words = shlex_split(&out)?;
    words
        .into_iter()
        .next()
        .ok_or_else(|| "empty unquoted token".to_string())
}

pub(crate) fn try_shell_tokens(seg: &str) -> Result<Vec<ShellToken>, String> {
    let chars: Vec<char> = seg.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut target = false;

    while i < n {
        if is_blank(chars[i]) {
            i += 1;
            continue;
        }
        if let Some((end, op, fd)) = match_redirect_op(&chars, i, target) {
            let raw: String = chars[i..end].iter().collect();
            out.push(ShellToken::Redirect { op, fd, raw });
            i = end;
            target = true;
            continue;
        }

        let start = i;
        let mut quote: Option<char> = None;
        let mut ansi = false;
        let mut dollar = false;
        let mut cuts: Vec<(usize, usize)> = Vec::new();

        while i < n {
            let ch = chars[i];
            if ch == '\\' && (quote != Some(SQ) || ansi) {
                i += 2;
                dollar = false;
                continue;
            }
            if let Some(q) = quote {
                if ch == q {
                    quote = None;
                    ansi = false;
                }
            } else if ch == SQ || ch == DQ {
                quote = Some(ch);
                ansi = ch == SQ && dollar;
            } else if is_blank(ch) || matches!(ch, '<' | '>' | '&') {
                break;
            } else if ch == '$' {
                if let Some(end) = match_ifs_expansion(&chars, i) {
                    cuts.push((i, end));
                    i = end;
                    dollar = false;
                    continue;
                }
            }
            dollar = quote.is_none() && ch == '$';
            i += 1;
        }

        if i == start {
            return Err("unexpected operator".to_string());
        }
        let end_i = i.min(n);
        let mut edges = Vec::with_capacity(2 + cuts.len() * 2);
        edges.push(start);
        for (a, b) in cuts {
            edges.push(a);
            edges.push(b);
        }
        edges.push(end_i);

        let mut pieces: Vec<String> = Vec::new();
        let mut k = 0;
        while k + 1 < edges.len() {
            let piece: String = chars[edges[k]..edges[k + 1]].iter().collect();
            if !piece.is_empty() {
                pieces.push(piece);
            }
            k += 2;
        }
        if pieces.is_empty() {
            pieces.push(chars[start..end_i].iter().collect());
        }
        for piece in pieces {
            let val = unquote_word(&piece)?;
            out.push(ShellToken::Word { val, raw: piece });
        }
        target = false;
    }

    Ok(out)
}

/// Fallible port of `_tokenize` (`L2832–2843`) returning `Result<(args, writes), String>`.
pub fn try_tokenize_seg(seg: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let mut args = Vec::new();
    let mut writes = Vec::new();
    let mut pending: Option<String> = None;

    for tok in try_shell_tokens(seg)? {
        match tok {
            ShellToken::Redirect { op, .. } => {
                pending = Some(op);
            }
            ShellToken::Word { val, .. } => {
                if let Some(op) = pending.take() {
                    if is_write_redirect_op(&op) {
                        writes.push(val);
                    }
                } else {
                    args.push(val);
                }
            }
        }
    }

    Ok((args, writes))
}

/// Exact port of `_tokenize` (`L2832–2843`) returning `(args, writes)`.
pub fn tokenize_seg(seg: &str) -> (Vec<String>, Vec<String>) {
    try_tokenize_seg(seg).unwrap_or_else(|_| {
        (
            seg.split_whitespace().map(str::to_string).collect(),
            Vec::new(),
        )
    })
}

/// Exact port of `_peel_busybox` (`L2882–2888`).
pub fn peel_busybox(head: &str, rest: &[String]) -> (String, Vec<String>) {
    if matches!(head, "busybox" | "busybox.static" | "toybox")
        && rest.first().is_some_and(|w| is_busybox_applet(w))
    {
        return (rest[0].clone(), rest[1..].to_vec());
    }
    (head.to_string(), rest.to_vec())
}

pub(crate) fn split_env_string(text: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut i = 0;

    let flush = |words: &mut Vec<String>, cur: &mut String, started: &mut bool| {
        if *started {
            words.push(std::mem::take(cur));
            *started = false;
        }
    };

    while i < n {
        let ch = chars[i];
        if ch == '\\' {
            if i + 1 == n {
                return Err("env -S ends in a backslash".to_string());
            }
            let nxt = chars[i + 1];
            if quote == Some(SQ) && nxt != SQ && nxt != '\\' {
                cur.push(ch);
                started = true;
                i += 1;
                continue;
            }
            if nxt == 'c' {
                if quote.is_some() {
                    return Err("env -S has a quoted stop escape".to_string());
                }
                break;
            }
            if nxt == '_' && quote.is_none() {
                flush(&mut words, &mut cur, &mut started);
            } else {
                let mapped = match nxt {
                    'f' => '\x0c',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'v' => '\x0b',
                    '_' => ' ',
                    '#' => '#',
                    '$' => '$',
                    '"' => '"',
                    '\'' => '\'',
                    '\\' => '\\',
                    _ => return Err("unsupported env -S escape".to_string()),
                };
                cur.push(mapped);
                started = true;
            }
            i += 2;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && (ch == SQ || ch == DQ) {
            quote = Some(ch);
            started = true;
        } else if quote != Some(SQ) && ch == '$' {
            return Err("env -S environment expansion cannot prove a receipt".to_string());
        } else if quote.is_none() && ch == '#' && !started {
            break;
        } else if quote.is_none() && matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
            flush(&mut words, &mut cur, &mut started);
        } else {
            cur.push(ch);
            started = true;
        }
        i += 1;
    }

    if quote.is_some() {
        return Err("unclosed env -S quote".to_string());
    }
    flush(&mut words, &mut cur, &mut started);
    Ok(words)
}

pub(crate) fn peel_wrapper(
    ws: &[String],
    operand_flags: &[&str],
    is_env: bool,
) -> Result<(Vec<String>, bool), String> {
    let mut cur: Vec<String> = ws[1..].to_vec();
    while !cur.is_empty() {
        let word = cur[0].clone();
        if matches!(word.as_str(), "-V" | "--help" | "--version") {
            return Ok((ws.to_vec(), true));
        }
        if word == "--" {
            return Ok((cur[1..].to_vec(), false));
        }
        if is_env && matches!(word.as_str(), "-S" | "--split-string") && cur.len() > 1 {
            let mut next = split_env_string(&cur[1])?;
            next.extend_from_slice(&cur[2..]);
            cur = next;
            continue;
        }
        if is_env {
            if let Some(val) = word.strip_prefix("--split-string=") {
                let mut next = split_env_string(val)?;
                next.extend_from_slice(&cur[1..]);
                cur = next;
                continue;
            }
            if let Some(val) = word.strip_prefix("-S") {
                if !val.is_empty() {
                    let mut next = split_env_string(val)?;
                    next.extend_from_slice(&cur[1..]);
                    cur = next;
                    continue;
                }
            }
        }
        if operand_flags.contains(&word.as_str()) && cur.len() > 1 {
            cur = cur[2..].to_vec();
        } else if is_env && word.starts_with('-') {
            let allowed_exact = matches!(
                word.as_str(),
                "-" | "-i" | "--ignore-environment" | "-v" | "--debug"
            );
            let allowed_long_eq = operand_flags.iter().any(|flag| {
                flag.starts_with("--")
                    && word
                        .strip_prefix(*flag)
                        .is_some_and(|rest| rest.starts_with('='))
            });
            if !allowed_exact && !allowed_long_eq {
                return Err("unsupported env option".to_string());
            }
            cur = cur[1..].to_vec();
        } else if word.starts_with('-') {
            cur = cur[1..].to_vec();
        } else {
            return Ok((cur, false));
        }
    }
    Ok((cur, false))
}

pub(crate) fn peel_sudo(ws: &[String]) -> (Vec<String>, bool) {
    let mut i = 1;
    while i < ws.len() {
        let word = ws[i].as_str();
        if matches!(word, "-V" | "--help" | "--version") {
            return (ws.to_vec(), true);
        }
        if word == "sudo" {
            i += 1;
        } else if word == "--" {
            return (ws[i + 1..].to_vec(), false);
        } else if word.starts_with("--") && word.contains('=') {
            i += 1;
        } else if SUDO_OPERAND_FLAGS.contains(&word) && i + 1 < ws.len() {
            i += 2;
        } else if word.starts_with('-') && word != "-" {
            i += 1;
        } else {
            return (ws[i..].to_vec(), false);
        }
    }
    (Vec::new(), false)
}

pub(crate) fn peel_launcher(
    ws: &[String],
    short_arg: &str,
    long_arg: &[&str],
    positional: usize,
) -> (Vec<String>, bool) {
    let mut i = 1;
    while i < ws.len() {
        let word = ws[i].as_str();
        if matches!(word, "--help" | "--version") {
            return (ws.to_vec(), true);
        }
        if word == "--" {
            i += 1;
            break;
        }
        if word.starts_with("--") {
            let name = word.split('=').next().unwrap_or(word);
            let takes = !word.contains('=')
                && name.len() > 2
                && long_arg.iter().any(|o| o.starts_with(name));
            i += if takes { 2 } else { 1 };
        } else if word.starts_with('-') && word.len() > 1 {
            let cluster: Vec<char> = word[1..].chars().collect();
            let mut used = 1;
            for (k, &flag) in cluster.iter().enumerate() {
                if short_arg.contains(flag) {
                    used = if k + 1 == cluster.len() { 2 } else { 1 };
                    break;
                }
            }
            i += used;
        } else {
            break;
        }
    }
    let start = i.saturating_add(positional).min(ws.len());
    (ws[start..].to_vec(), false)
}

fn is_func_brace_head(word: &str) -> bool {
    let Some(prefix) = word.strip_suffix("(){") else {
        return false;
    };
    let mut chars = prefix.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

pub(crate) fn plain_words(
    args: &[String],
    peel_bang: bool,
    mode: PeelMode,
    mut assigns: Option<&mut Vec<String>>,
) -> Result<Vec<String>, String> {
    let mut ws = args.to_vec();
    let extended = mode != PeelMode::Basic;

    while !ws.is_empty() {
        let first = ws[0].clone();
        let is_opener_ch = |c: char| c == '{' || c == '(' || (peel_bang && c == '!');
        let head = if extended {
            basename(&first).to_string()
        } else {
            first.clone()
        };

        if first.len() == 1 && first.chars().next().is_some_and(is_opener_ch) {
            ws = ws[1..].to_vec();
        } else if first.len() > 1 && first.chars().next().is_some_and(is_opener_ch) {
            let mut next = Vec::with_capacity(ws.len());
            next.push(first[1..].to_string());
            next.extend_from_slice(&ws[1..]);
            ws = next;
        } else if is_env_assign(&first) {
            if let Some(ref mut target) = assigns {
                target.push(first);
            }
            ws = ws[1..].to_vec();
        } else if head == "sudo" {
            let (peeled, stopped) = peel_sudo(&ws);
            if stopped {
                return Ok(ws);
            }
            ws = peeled;
        } else if let Some(op_flags) = wrapper_operands(&head) {
            let (peeled, stopped) = peel_wrapper(&ws, op_flags, head == "env")?;
            if stopped {
                return Ok(ws);
            }
            ws = peeled;
        } else if is_wrapper_word(&head) {
            if extended && ws.get(1).is_some_and(|w| matches!(w.as_str(), "-v" | "-V")) {
                return Ok(ws);
            }
            if extended && ws.get(1).is_some_and(|w| w == "-p") {
                ws = ws[2.min(ws.len())..].to_vec();
            } else {
                ws = ws[1..].to_vec();
            }
        } else if extended
            && (mode != PeelMode::Receipt || is_receipt_launcher(&head))
            && launcher_spec(&head).is_some()
        {
            let (short_arg, long_arg, positional) = launcher_spec(&head).unwrap_or(("", &[], 0));
            let (peeled, stopped) = peel_launcher(&ws, short_arg, long_arg, positional);
            if stopped {
                return Ok(ws);
            }
            ws = peeled;
        } else if extended && is_keyword(&head) {
            ws = ws[1..].to_vec();
        } else if extended && head == "case" {
            ws = ws[3.min(ws.len())..].to_vec();
        } else if extended && head == "coproc" {
            if ws
                .get(2)
                .is_some_and(|w| w.starts_with('{') || w.starts_with('('))
            {
                ws = ws[2..].to_vec();
            } else {
                ws = ws[1..].to_vec();
            }
        } else if extended
            && ((head == "function" && ws.len() > 1) || ws.get(1).is_some_and(|w| w == "()"))
        {
            ws = ws[2..].to_vec();
        } else if extended
            && (is_func_brace_head(&first)
                || (first.len() > 1
                    && first.ends_with(')')
                    && (first.ends_with("()") || !first.contains('('))))
        {
            ws = ws[1..].to_vec();
        } else {
            return Ok(ws);
        }
    }

    Ok(ws)
}

/// Fallible port of `_command_words` (`L2078–2097`) returning `Result<(assigns, words), String>`.
pub fn try_command_words_with_assigns(
    args: &[String],
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut assigns = Vec::new();
    let mut ws = args.to_vec();
    if ws.last().is_some_and(|w| w.ends_with(')')) {
        if let Some(last) = ws.pop() {
            let trimmed = last.trim_end_matches(')');
            if !trimmed.is_empty() {
                ws.push(trimmed.to_string());
            }
        }
    }
    ws = plain_words(&ws, true, PeelMode::Extended, Some(&mut assigns))?;
    while !ws.is_empty() {
        let (head, rest) = peel_busybox(basename(&ws[0]), &ws[1..]);
        if rest.len() == ws.len() - 1 {
            break;
        }
        let mut next = Vec::with_capacity(1 + rest.len());
        next.push(head);
        next.extend(rest);
        ws = plain_words(&next, true, PeelMode::Extended, Some(&mut assigns))?;
    }
    Ok((assigns, ws))
}

/// Exact port of `_command_words` (`L2078–2097`) returning `(assigns, words)`.
pub fn command_words_with_assigns(args: &[String]) -> (Vec<String>, Vec<String>) {
    try_command_words_with_assigns(args).unwrap_or_else(|_| (Vec::new(), args.to_vec()))
}

/// Full 4-tuple port of `_gh_alias` (`L3323–3337`): `(verb, name, expansion, runs_in_shell)`.
pub fn gh_alias_detail(ws: &[String]) -> Option<(String, Option<String>, Option<String>, bool)> {
    if ws.is_empty() {
        return None;
    }
    let rest = &ws[1..];
    let mut i = 0;
    while i < rest.len() && rest[i].starts_with('-') {
        i += if GH_OPERAND_FLAGS.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    if rest.get(i).map(String::as_str) != Some("alias") {
        return None;
    }
    let tail = &rest[i + 1..];
    let ops: Vec<&String> = tail.iter().filter(|w| !w.starts_with('-')).collect();
    if ops.is_empty() {
        return None;
    }
    if ops[0] == "set" && ops.len() >= 3 {
        let shell =
            tail.iter().any(|w| matches!(w.as_str(), "-s" | "--shell")) || ops[2].starts_with('!');
        let expansion = ops[2].trim_start_matches('!').to_string();
        return Some((
            "set".to_string(),
            Some(ops[1].clone()),
            Some(expansion),
            shell,
        ));
    }
    Some((ops[0].clone(), None, None, false))
}

/// Compact `(verb, rest)` view of `gh alias ...`; see `gh_alias_detail` for the full 4-tuple.
pub fn gh_alias(ws: &[String]) -> Option<(String, Vec<String>)> {
    if ws.is_empty() {
        return None;
    }
    let rest = &ws[1..];
    let mut i = 0;
    while i < rest.len() && rest[i].starts_with('-') {
        i += if GH_OPERAND_FLAGS.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    if rest.get(i).map(String::as_str) != Some("alias") {
        return None;
    }
    let tail = &rest[i + 1..];
    let ops: Vec<String> = tail
        .iter()
        .filter(|w| !w.starts_with('-'))
        .cloned()
        .collect();
    if ops.is_empty() {
        return None;
    }
    Some((ops[0].clone(), ops[1..].to_vec()))
}

fn gh_writes_has(group: &str, verb: &str) -> bool {
    let verbs: &[&str] = match group {
        "repo" => &[
            "create",
            "delete",
            "archive",
            "unarchive",
            "rename",
            "edit",
            "fork",
            "sync",
        ],
        "workflow" => &["run", "enable", "disable"],
        "run" => &["cancel", "rerun", "delete"],
        "gist" => &["create", "edit", "delete", "rename"],
        "variable" => &["set", "delete"],
        "cache" => &["delete"],
        "label" => &["create", "edit", "delete", "clone"],
        "ssh-key" | "gpg-key" => &["add", "delete"],
        "codespace" => &["create", "delete", "edit", "stop", "rebuild"],
        "project" => &[
            "create",
            "delete",
            "edit",
            "close",
            "copy",
            "link",
            "unlink",
            "mark-template",
            "item-add",
            "item-create",
            "item-edit",
            "item-delete",
            "item-archive",
            "field-create",
            "field-delete",
        ],
        _ => return false,
    };
    verbs.contains(&verb)
}

/// Fallible port of `_is_send` (`L2320–2406`).
pub fn try_is_send_words(args: &[String]) -> Result<bool, String> {
    let (_assigns, ws) = try_command_words_with_assigns(args)?;
    let Some(first) = ws.first() else {
        return Ok(false);
    };
    if first != "gh" && !first.ends_with("/gh") {
        return Ok(false);
    }
    let rest = &ws[1..];
    let mut i = 0;
    while i < rest.len() && rest[i].starts_with('-') {
        i += if GH_OPERAND_FLAGS.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    if i >= rest.len() {
        return Ok(false);
    }
    let group = rest[i].as_str();
    let tail = &rest[i + 1..];

    if group == "api" {
        let mut method: Option<String> = None;
        let mut fields = false;
        let mut has_input = false;
        let mut j = 0;
        while j < tail.len() {
            let word = tail[j].as_str();
            if word == "--" {
                break;
            }
            if word.starts_with("--") {
                let (opt, eq_val) = match word.split_once('=') {
                    Some((k, v)) => (k, Some(v)),
                    None => (word, None),
                };
                if opt == "--method" {
                    if let Some(val) = eq_val {
                        method = Some(val.to_ascii_uppercase());
                        j += 1;
                    } else if j + 1 < tail.len() {
                        method = Some(tail[j + 1].to_ascii_uppercase());
                        j += 2;
                    } else {
                        j += 1;
                    }
                    continue;
                }
                if matches!(opt, "--field" | "--raw-field" | "--input") {
                    fields = true;
                    if opt == "--input" {
                        has_input = true;
                    }
                    j += if eq_val.is_some() { 1 } else { 2 };
                    continue;
                }
                if GH_API_VAL_LONG.contains(&opt) && eq_val.is_none() {
                    j += 2;
                    continue;
                }
                j += 1;
                continue;
            }
            if word.starts_with('-') && word.len() > 1 {
                let cluster: Vec<char> = word[1..].chars().collect();
                let mut step = 1;
                for (k, &ch) in cluster.iter().enumerate() {
                    if ch == 'X' {
                        let rem: String = cluster[k + 1..].iter().collect();
                        if !rem.is_empty() {
                            method = Some(rem.to_ascii_uppercase());
                        } else if j + 1 < tail.len() {
                            method = Some(tail[j + 1].to_ascii_uppercase());
                            step = 2;
                        }
                        break;
                    }
                    if ch == 'f' || ch == 'F' {
                        fields = true;
                        if k + 1 == cluster.len() {
                            step = 2;
                        }
                        break;
                    }
                    if GH_API_VAL_SHORT.contains(ch) {
                        if k + 1 == cluster.len() {
                            step = 2;
                        }
                        break;
                    }
                }
                j += step;
                continue;
            }
            j += 1;
        }
        if has_input {
            return Ok(true);
        }
        if let Some(m) = method {
            return Ok(matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"));
        }
        return Ok(fields);
    }

    let mut verbs: Vec<&str> = Vec::new();
    let mut j = 0;
    while j < tail.len() && verbs.len() < 2 {
        if GH_OPERAND_FLAGS.contains(&tail[j].as_str()) {
            j += 2;
            continue;
        }
        if !tail[j].starts_with('-') {
            verbs.push(tail[j].as_str());
        }
        j += 1;
    }
    if verbs.is_empty() {
        return Ok(false);
    }
    if matches!(group, "pr" | "issue" | "release") {
        return Ok(SEND_VERBS.contains(&verbs[0]));
    }
    if group == "repo" && matches!(verbs[0], "deploy-key" | "autolink") {
        return Ok(matches!(
            verbs.get(1).copied(),
            Some("add" | "create" | "delete")
        ));
    }
    Ok(gh_writes_has(group, verbs[0]))
}

/// Exact port of `_is_send` (`L2320–2406`).
pub fn is_send_words(args: &[String]) -> bool {
    try_is_send_words(args).unwrap_or(false)
}

/// Exact port of `_git_bodies` (`L3447–3498`): `git bisect run`, `git rebase -x/--exec`,
/// `git submodule foreach`.
pub fn git_bodies(rest: &[String]) -> Vec<String> {
    let mut i = 0;
    while i < rest.len() && rest[i].starts_with('-') {
        i += if GIT_GLOBAL_ARG.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    let (sub, args) = if i < rest.len() {
        (rest[i].as_str(), &rest[i + 1..])
    } else {
        ("", &rest[0..0])
    };
    let mut out = Vec::new();

    if sub == "bisect" {
        if args.first().map(String::as_str) == Some("run") && args.len() > 1 {
            out.push(shlex_join(&args[1..]));
        }
    } else if sub == "rebase" {
        let mut k = 0;
        while k < args.len() {
            let w = args[k].as_str();
            if let Some(after) = w.strip_prefix("--") {
                let (name, eq_val) = match after.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (after, None),
                };
                if name.len() >= 2 && "exec".starts_with(name) {
                    if let Some(val) = eq_val {
                        out.push(val.to_string());
                    } else if k + 1 < args.len() {
                        k += 1;
                        out.push(args[k].clone());
                    }
                }
            } else if let Some(short_rest) = w.strip_prefix('-') {
                let chars: Vec<char> = short_rest.chars().collect();
                for (j, &flag) in chars.iter().enumerate() {
                    if matches!(flag, 'x' | 's' | 'X') {
                        let mut operand: String = chars[j + 1..].iter().collect();
                        if operand.is_empty() && k + 1 < args.len() {
                            k += 1;
                            operand = args[k].clone();
                        }
                        if flag == 'x' {
                            out.push(operand);
                        }
                        break;
                    }
                    if matches!(flag, 'S' | 'C') {
                        break;
                    }
                }
            }
            k += 1;
        }
    } else if matches!(sub, "submodule" | "submodule--helper") {
        let mut k = 0;
        while k < args.len() && args[k].starts_with('-') {
            k += 1;
        }
        if args.get(k).map(String::as_str) == Some("foreach") {
            k += 1;
            while k < args.len()
                && matches!(args[k].as_str(), "--recursive" | "--quiet" | "-q" | "--")
            {
                let is_dd = args[k] == "--";
                k += 1;
                if is_dd {
                    break;
                }
            }
            let cmd = &args[k..];
            if cmd.len() == 1 {
                out.push(cmd[0].clone());
            } else if !cmd.is_empty() {
                out.push(shlex_join(cmd));
            }
        }
    }

    out
}

fn coarse_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:&>>?|>>|>\||>&|<>|>)[ \t]*([^ \t\n;&|<>()]+)")
            .expect("valid coarse write regex")
    })
}

/// Exact port of `_coarse_writes` (`L4215–4224`) keeping `(unquoted, raw)` pairs.
pub fn coarse_writes_raw(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for caps in coarse_write_re().captures_iter(text) {
        let word = &caps[1];
        let is_fd_or_dash =
            word == "-" || (!word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()));
        if !is_fd_or_dash {
            let unq = word.trim_matches(|c| c == SQ || c == DQ).to_string();
            out.push((unq, word.to_string()));
        }
    }
    out
}

/// Unquoted targets of `_coarse_writes` (`L4215–4224`).
pub fn coarse_writes(text: &str) -> Vec<String> {
    coarse_writes_raw(text)
        .into_iter()
        .map(|(u, _)| u)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_split_and_quote_parity() {
        assert_eq!(shlex_split("").unwrap(), Vec::<String>::new());
        assert_eq!(shlex_split("''").unwrap(), vec!["".to_string()]);
        assert_eq!(
            shlex_split(r#"echo "a\"b\\c\$d" 'e\nf'"#).unwrap(),
            vec!["echo", r#"a"b\c\$d"#, r"e\nf"]
        );
        assert!(shlex_split("echo 'unclosed").is_err());
        assert!(shlex_split("a\\").is_err());
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("plain/path-1.txt"), "plain/path-1.txt");
        assert_eq!(shlex_quote("a b'c"), "'a b'\"'\"'c'");
        assert_eq!(
            shlex_join(&["git".to_string(), "commit".to_string(), "a b".to_string()]),
            "git commit 'a b'"
        );
    }

    #[test]
    fn fnmatchcase_parity() {
        assert!(fnmatchcase("a\nb", "a*b"));
        assert!(fnmatchcase("a\nb", "a?b"));
        assert!(fnmatchcase("a", "[!]]"));
        assert!(fnmatchcase("]", "[]]"));
        assert!(fnmatchcase("]", "[]a]"));
        assert!(fnmatchcase("\\", "[\\]"));
        assert!(fnmatchcase("b", "[a-c]"));
        assert!(!fnmatchcase("b", "[c-a]"));
        assert!(!fnmatchcase("a", "[!]"));
        assert!(fnmatchcase("[!]", "[!]"));
        assert!(!fnmatchcase("Foo", "foo"));
    }

    #[test]
    fn home_and_sh_home_path_parity() {
        assert_eq!(home_path("~", "/home/u/"), "/home/u");
        assert_eq!(home_path("~/a", "/home/u/"), "/home/u/a");
        assert_eq!(home_path("~/", "/"), "/");
        assert_eq!(home_path("$HOME/.bashrc", "/home/u"), "/home/u/.bashrc");
        assert_eq!(home_path("${HOME}/x", "/home/u"), "/home/u/x");
        assert_eq!(home_path("$HOME2/x", "/home/u"), "$HOME2/x");

        assert_eq!(sh_home_path("~/.bashrc", "~/.bashrc", "/h"), "/h/.bashrc");
        assert_eq!(sh_home_path("~/.bashrc", "'~/.bashrc'", "/h"), "~/.bashrc");
        assert_eq!(sh_home_path("$HOME/x", "\"$HOME/x\"", "/h"), "/h/x");
        assert_eq!(sh_home_path("$HOME/x", "'$HOME/x'", "/h"), "$HOME/x");
    }

    #[test]
    fn unquote_c_and_patch_targets_parity() {
        assert_eq!(
            unquote_c_path(r#""b/.claude/\163ettings.json""#),
            "b/.claude/settings.json"
        );
        let blob = "*** Begin Patch\n*** Update File: src/a.rs\n*** Move to: src/b.rs\n+++ \"b/.claude/\\163ettings.json\"\t2026\n--- /dev/null\n";
        assert_eq!(
            patch_targets(blob),
            vec!["src/a.rs", "src/b.rs", ".claude/settings.json"]
        );
    }

    #[test]
    fn split_and_tokenize_parity() {
        let segs = split_segments("echo ok && # comment\ngit status | cat");
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].0, "start");
        assert_eq!(segs[1].0, "&&");
        assert_eq!(segs[2].0, "|");

        let (args, writes) = try_tokenize_seg(r"rm$IFS-rf$IFS/ >out.txt").unwrap();
        assert_eq!(args, vec!["rm", "-rf", "/"]);
        assert_eq!(writes, vec!["out.txt"]);

        let (args2, _) = try_tokenize_seg(r"$'\x72m' -rf /").unwrap();
        assert_eq!(args2, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn command_peeling_and_gh_send_parity() {
        let raw: Vec<String> = [
            "env", "-i", "FOO=1", "sudo", "-u", "root", "busybox", "rm", "-rf", "/",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let (assigns, ws) = try_command_words_with_assigns(&raw).unwrap();
        assert_eq!(assigns, vec!["FOO=1"]);
        assert_eq!(ws, vec!["rm", "-rf", "/"]);

        let send_args: Vec<String> = ["gh", "api", "-iX", "POST", "repos/o/r/issues"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(is_send_words(&send_args));

        let read_args: Vec<String> = ["gh", "api", "--method", "GET", "-f", "a=1", "repos/o/r"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(!is_send_words(&read_args));

        let alias_ws: Vec<String> = ["gh", "alias", "set", "-s", "x", "gh pr merge 1"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            gh_alias_detail(&alias_ws),
            Some((
                "set".to_string(),
                Some("x".to_string()),
                Some("gh pr merge 1".to_string()),
                true
            ))
        );
        assert_eq!(
            gh_alias(&alias_ws),
            Some((
                "set".to_string(),
                vec!["x".to_string(), "gh pr merge 1".to_string()]
            ))
        );
    }

    #[test]
    fn git_bodies_and_coarse_writes_parity() {
        let rest: Vec<String> = ["-C", "repo", "rebase", "--ex", "rm -rf /", "main"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(git_bodies(&rest), vec!["rm -rf /"]);

        assert_eq!(
            coarse_writes("echo hi > 'a.txt' 2>&1 >> /tmp/b"),
            vec!["a.txt", "/tmp/b"]
        );
    }
}
