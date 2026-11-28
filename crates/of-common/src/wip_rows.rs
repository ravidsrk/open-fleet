//! CommonMark-aware WIP-curve section and table row extractor shared by
//! `of_verify::run_report` and `of_ledgers::events` (port of `run_report.py` §WIP-curve).

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

pub const WIP_SECTION: &str = "## WIP-curve protocol row";

pub const WIP_ROW_KEYS: &[&str] = &[
    "wave",
    "builders",
    "reviewers",
    "throughput",
    "latency_median",
    "latency_max",
    "rework",
    "freshness",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipRow {
    pub raw: String,
    pub cells: BTreeMap<String, String>,
    pub doubled: Vec<String>,
}

fn wip_section_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^ {0,3}#{1,6}[ \t]+WIP-curve[ \t]+protocol[ \t]+row\b").expect("regex")
    })
}

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^ {0,3}#{1,6}(?:[ \t]|$)").expect("regex"))
}

fn setext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^ {0,3}(?:=+|-+)[ \t]*$").expect("regex"))
}

fn quote_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^ {0,3}>").expect("regex"))
}

fn cell_kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([a-z_]+)=([^\s|`]*)").expect("regex"))
}

pub fn expand_tabs_4(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut col = 0usize;
    for ch in raw.chars() {
        if ch == '\t' {
            let spaces = 4 - (col % 4);
            for _ in 0..spaces {
                out.push(' ');
            }
            col += spaces;
        } else {
            out.push(ch);
            col += 1;
        }
    }
    out
}

fn indent_from(line: &str, start: usize) -> usize {
    let rest = line.get(start..).unwrap_or("");
    let trimmed = rest.trim_start_matches(' ');
    rest.len() - trimmed.len()
}

fn match_fence(line: &str, col: usize) -> Option<(String, usize)> {
    let rest = line.get(col..)?;
    let leading = rest.bytes().take_while(|&b| b == b' ').count();
    if leading > 3 {
        return None;
    }
    let after = &rest[leading..];
    let first = *after.as_bytes().first()?;
    if first == b'`' {
        let run = after.bytes().take_while(|&b| b == b'`').count();
        if run < 3 {
            return None;
        }
        let tail = &after[run..];
        if tail.contains('`') {
            return None;
        }
        return Some((after[..run].to_string(), col + leading + run));
    }
    if first == b'~' {
        let run = after.bytes().take_while(|&b| b == b'~').count();
        if run < 3 {
            return None;
        }
        return Some((after[..run].to_string(), col + leading + run));
    }
    None
}

fn is_thematic_break(line: &str, base: usize) -> bool {
    let Some(rest) = line.get(base..) else {
        return false;
    };
    let leading = rest.bytes().take_while(|&b| b == b' ').count();
    if leading > 3 {
        return false;
    }
    let after = &rest[leading..];
    let Some(&ch) = after.as_bytes().first() else {
        return false;
    };
    if ch != b'-' && ch != b'*' && ch != b'_' {
        return false;
    }
    let mut count = 0usize;
    for b in after.bytes() {
        if b == ch {
            count += 1;
        } else if b == b' ' || b == b'\t' {
            continue;
        } else {
            return false;
        }
    }
    count >= 3
}

/// Returns `(ordered_num, end_byte_offset)` if a CommonMark list item marker starts at `base`.
fn match_list_item(line: &str, base: usize) -> Option<(Option<u64>, usize)> {
    let rest = line.get(base..)?;
    let leading = rest.bytes().take_while(|&b| b == b' ').count();
    if leading > 3 {
        return None;
    }
    let after = &rest[leading..];
    let first = *after.as_bytes().first()?;
    if matches!(first, b'-' | b'+' | b'*') {
        let end = base + leading + 1;
        let next = line.as_bytes().get(end).copied();
        if matches!(next, None | Some(b' ') | Some(b'\t')) {
            return Some((None, end));
        }
        return None;
    }
    if first.is_ascii_digit() {
        let digits = after.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        let delim = *after.as_bytes().get(digits)?;
        if delim != b'.' && delim != b')' {
            return None;
        }
        let end = base + leading + digits + 1;
        let next = line.as_bytes().get(end).copied();
        if matches!(next, None | Some(b' ') | Some(b'\t')) {
            let num = after[..digits].parse::<u64>().ok()?;
            return Some((Some(num), end));
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParaCol {
    At(usize),
    Quoted,
}

pub fn wip_section_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut fence: Option<(String, usize)> = None;
    let mut para: Option<ParaCol> = None;
    let mut items: Vec<usize> = Vec::new();
    let mut empty = false;

    // Match Python's `str.splitlines()` behavior on \r\n, \n, \r.
    for raw in split_python_lines(text) {
        let line = expand_tabs_4(raw);
        let indent = indent_from(&line, 0);

        if let Some((ref fchar, col)) = fence.clone() {
            if !line.trim().is_empty() && indent < col {
                fence = None;
            } else {
                if let Some((closer, end_pos)) = match_fence(&line, col) {
                    if closer.as_bytes().first() == fchar.as_bytes().first()
                        && closer.len() >= fchar.len()
                        && line.get(end_pos..).unwrap_or("").trim().is_empty()
                    {
                        fence = None;
                    }
                }
                continue;
            }
        }

        if line.trim().is_empty() {
            if empty {
                items.pop();
            }
            para = None;
            empty = false;
            continue;
        }

        let mut kept = items.len();
        while kept > 0 && items[kept - 1] > indent {
            kept -= 1;
        }
        let mut base = if kept > 0 { items[kept - 1] } else { 0 };
        let mut opened: Vec<usize> = Vec::new();

        while !is_thematic_break(&line, base) {
            let Some((ord_num, item_end)) = match_list_item(&line, base) else {
                break;
            };
            let rest = line.get(item_end..).unwrap_or("");
            if opened.is_empty()
                && para == Some(ParaCol::At(base))
                && !(!rest.trim().is_empty() && ord_num.unwrap_or(1) == 1)
            {
                break;
            }
            let gap = indent_from(&line, item_end);
            base = item_end
                + if !rest.trim().is_empty() && gap > 0 && gap <= 4 {
                    gap
                } else {
                    1
                };
            opened.push(base);
        }

        empty = !opened.is_empty() && line.get(base..).unwrap_or("").trim().is_empty();
        let opener = match_fence(&line, base);
        let heading = heading_re().is_match(&line);
        let setext = opened.is_empty()
            && match para {
                Some(ParaCol::At(p)) => {
                    indent >= p && line.get(p..).is_some_and(|s| setext_re().is_match(s))
                }
                _ => false,
            };

        if let Some((fchars, _)) = &opener {
            fence = Some((fchars.clone(), base));
        } else if heading {
            inside = wip_section_re().is_match(&line);
        } else if setext {
            inside = false;
        } else if inside {
            out.push(raw.to_string());
        }

        let quote = line.get(base..).is_some_and(|s| quote_re().is_match(s));
        if opener.is_some()
            || heading
            || setext
            || is_thematic_break(&line, base)
            || line.trim_start().starts_with('|')
        {
            items.truncate(kept);
            items.extend(opened);
            para = None;
        } else if !opened.is_empty() || para.is_none() || quote {
            items.truncate(kept);
            items.extend(opened);
            para = if quote {
                Some(ParaCol::Quoted)
            } else if !line.get(base..).unwrap_or("").trim().is_empty()
                && indent_from(&line, base) < 4
            {
                Some(ParaCol::At(base))
            } else {
                None
            };
        }
    }

    out
}

pub fn split_python_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = text[i..].chars().next().expect("char");
        let len = ch.len_utf8();
        if ch == '\r' {
            lines.push(&text[start..i]);
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
            start = i;
        } else if matches!(
            ch,
            '\n' | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            lines.push(&text[start..i]);
            i += len;
            start = i;
        } else {
            i += len;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

fn is_python_word_or_eq(ch: char) -> bool {
    ch == '=' || ch == '_' || ch.is_alphanumeric()
}

pub fn parse_wip_cells(line: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for caps in cell_kv_re().captures_iter(line) {
        let m = caps.get(0).expect("match");
        if m.start() > 0 {
            if let Some(prev) = line[..m.start()].chars().next_back() {
                if is_python_word_or_eq(prev) {
                    continue;
                }
            }
        }
        pairs.push((caps[1].to_string(), caps[2].to_string()));
    }
    pairs
}

pub fn wip_rows(text: &str) -> Vec<WipRow> {
    let mut rows = Vec::new();
    for line in wip_section_lines(text) {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let pairs = parse_wip_cells(&line);
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for (k, _) in &pairs {
            *counts.entry(k.as_str()).or_insert(0) += 1;
        }
        if !counts.contains_key("wave") {
            continue;
        }
        let doubled: Vec<String> = counts
            .iter()
            .filter(|(_, &c)| c > 1)
            .map(|(k, _)| (*k).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut cells = BTreeMap::new();
        for (k, v) in pairs {
            cells.insert(k, v);
        }
        rows.push(WipRow {
            raw: line.trim().to_string(),
            cells,
            doubled,
        });
    }
    rows
}
