//! YAML-frontmatter and composition grammar parser mirroring
//! `runtime/scripts/_catalog_grammar.py`.

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub enum FmValue {
    Str(String),
    Map(BTreeMap<String, FmValue>),
}

impl FmValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FmValue::Str(s) => Some(s.as_str()),
            FmValue::Map(_) => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, FmValue>> {
        match self {
            FmValue::Map(m) => Some(m),
            FmValue::Str(_) => None,
        }
    }
}

fn block_scalar_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[|>](?:[1-9]?[+-]?|[+-]?[1-9]?)$").expect("regex"))
}

fn key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([A-Za-z_-][A-Za-z0-9_-]*):(?:\s+(.*?))?\s*$").expect("regex"))
}

fn plain_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)#.*$").expect("regex"))
}

fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").expect("regex"))
}

fn compose_clause_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)\b(?:Composes|COMPOSES|composes|Rides|RIDES|rides)\b\s+(.+?)(?:\n\n|\z)")
            .expect("regex")
    })
}

fn deferred_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?ms)^[ \t*_]*DEFERRED READS\b(.+?)(?:\n\n|\z)").expect("regex"))
}

fn backtick_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([a-z0-9][a-z0-9-]*)`").expect("regex"))
}

fn md_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\w./-]+\.md\b").expect("regex"))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn is_comment(line: &str) -> bool {
    line.trim_start_matches([' ', '\t']).starts_with('#')
}

fn plain(value: &str) -> String {
    plain_comment_re().replace(value, "").trim().to_string()
}

fn closed(value: &str, quote: char) -> bool {
    value.len() >= 2 && value.ends_with(quote)
}

fn parse_quoted(first: &str, rest: &[&str]) -> String {
    let quote = first.chars().next().unwrap_or('"');
    let mut joined = first.trim_end().to_string();
    for line in rest {
        if closed(&joined, quote) {
            break;
        }
        joined.push(' ');
        joined.push_str(line.trim());
        joined = joined.trim_end().to_string();
    }
    if !closed(&joined, quote) {
        return joined;
    }
    let inner = &joined[1..joined.len() - 1];
    if quote == '\'' {
        inner.replace("''", "'")
    } else {
        inner.replace("\\\"", "\"").replace("\\\\", "\\")
    }
}

fn parse_value(inline: &str, block: &[String], top: bool) -> Result<FmValue, String> {
    let content: Vec<&str> = block
        .iter()
        .map(|s| s.as_str())
        .filter(|l| !l.trim().is_empty())
        .collect();
    let indented: Vec<&str> = content
        .iter()
        .copied()
        .filter(|l| indent_of(l) > 0)
        .collect();
    if inline.starts_with('\'') || inline.starts_with('"') {
        return Ok(FmValue::Str(parse_quoted(inline, &indented)));
    }
    let head = plain(inline);
    if block_scalar_re().is_match(&head) {
        let joined = indented
            .iter()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(FmValue::Str(joined));
    }
    if !head.is_empty() {
        let mut parts = vec![head];
        for l in indented {
            if !is_comment(l) {
                let p = plain(l);
                if !p.is_empty() {
                    parts.push(p);
                }
            }
        }
        return Ok(FmValue::Str(parts.join(" ")));
    }
    let children: Vec<&str> = content.iter().copied().filter(|l| !is_comment(l)).collect();
    if children.is_empty() {
        return Ok(FmValue::Str(if top {
            "<object>".to_string()
        } else {
            String::new()
        }));
    }
    let first_child = children[0].trim();
    if key_re().is_match(first_child) {
        let width = indent_of(children[0]);
        let dedented: Vec<String> = block
            .iter()
            .map(|l| {
                let cut = width.min(indent_of(l));
                l[cut..].to_string()
            })
            .collect();
        return Ok(FmValue::Map(parse_mapping(&dedented, false)?));
    }
    if first_child == "-" || first_child.starts_with("- ") {
        return Ok(FmValue::Str("<object>".to_string()));
    }
    let joined = children
        .iter()
        .map(|l| plain(l))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(FmValue::Str(joined))
}

fn parse_mapping(lines: &[String], top: bool) -> Result<BTreeMap<String, FmValue>, String> {
    let mut data: BTreeMap<String, FmValue> = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        i += 1;
        if line.trim().is_empty() || is_comment(line) || indent_of(line) > 0 {
            continue;
        }
        let trimmed_end = line.trim_end();
        let Some(caps) = key_re().captures(trimmed_end) else {
            if top {
                return Err(format!(
                    "unreadable top-level frontmatter line: {:?}",
                    &line.trim()[..line.trim().len().min(60)]
                ));
            }
            continue;
        };
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        if data.contains_key(&key) {
            return Err(format!("duplicate frontmatter key {key:?}"));
        }
        let inline = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        let start = i;
        while i < lines.len()
            && (lines[i].trim().is_empty() || indent_of(&lines[i]) > 0 || is_comment(&lines[i]))
        {
            i += 1;
        }
        let val = parse_value(inline, &lines[start..i], top)?;
        data.insert(key, val);
    }
    Ok(data)
}

pub fn parse_frontmatter(text: &str) -> Result<BTreeMap<String, FmValue>, String> {
    let clean = text.strip_prefix('\u{feff}').unwrap_or(text);
    let norm = clean.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<String> = norm.split('\n').map(|s| s.to_string()).collect();
    if lines.is_empty() || lines[0].trim_end() != "---" {
        return Err("missing opening ---".to_string());
    }
    for end in 1..lines.len() {
        if lines[end].trim_end() == "---" {
            return parse_mapping(&lines[1..end], true);
        }
    }
    Err("missing closing ---".to_string())
}

pub fn split_body(text: &str) -> String {
    let norm = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = norm.split('\n').collect();
    if !lines.is_empty() && lines[0].trim() == "---" {
        for idx in 1..lines.len() {
            if lines[idx].trim() == "---" {
                return lines[idx + 1..].join("\n").trim().to_string();
            }
        }
    }
    text.trim().to_string()
}

pub fn bare_md_stems(text: &str) -> Vec<String> {
    let mut stems = Vec::new();
    for m in md_token_re().find_iter(text) {
        let tok = m.as_str();
        let before_colon = m.start() > 0 && text.as_bytes()[m.start() - 1] == b':';
        if tok.starts_with("//") || before_colon || tok.contains('/') {
            continue;
        }
        let stem = &tok[..tok.len() - 3];
        if name_re().is_match(stem) {
            stems.push(stem.to_string());
        }
    }
    stems
}

pub fn clause_refs(body: &str) -> Vec<String> {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    for caps in compose_clause_re().captures_iter(body) {
        let clause = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for bt in backtick_re().captures_iter(clause) {
            if let Some(m) = bt.get(1) {
                refs.insert(m.as_str().to_string());
            }
        }
        for stem in bare_md_stems(clause) {
            refs.insert(stem);
        }
    }
    refs.into_iter().collect()
}

pub fn is_valid_name(name: &str) -> bool {
    name_re().is_match(name)
}

pub fn compose_clause_backticks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for caps in compose_clause_re().captures_iter(text) {
        let clause = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for bt in backtick_re().captures_iter(clause) {
            if let Some(m) = bt.get(1) {
                out.push(m.as_str().to_string());
            }
        }
    }
    out
}

pub fn explicit_protocol_refs(text: &str) -> BTreeSet<String> {
    let mut refs: BTreeSet<String> = compose_clause_backticks(text).into_iter().collect();
    for stem in bare_md_stems(text) {
        refs.insert(stem);
    }
    refs
}

fn relative_link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([^\]]*)\]\(([A-Za-z0-9_./:-]+)(#[^)]*)?\)").expect("regex"))
}

fn word_cand_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9]+(?:-[a-z0-9]+)*").expect("regex"))
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

pub fn deferred_words(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for caps in deferred_re().captures_iter(text) {
        let para = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for m in word_cand_re().find_iter(para) {
            let start = m.start();
            let end = m.end();
            let prev_bad = para[..start]
                .chars()
                .next_back()
                .map(|c| is_word_char(c) || matches!(c, '.' | '/' | '-'))
                .unwrap_or(false);
            if prev_bad {
                continue;
            }
            let tail = &para[end..];
            let next_bad = tail
                .chars()
                .next()
                .map(|c| is_word_char(c) || matches!(c, '/' | '-'))
                .unwrap_or(false);
            if next_bad {
                continue;
            }
            if let Some(after_md) = tail.strip_prefix(".md") {
                let md_boundary = after_md
                    .chars()
                    .next()
                    .map(|c| !is_word_char(c))
                    .unwrap_or(true);
                if md_boundary {
                    continue;
                }
            }
            out.insert(m.as_str().to_string());
        }
    }
    out
}

pub fn protocol_mentions(text: &str) -> BTreeSet<String> {
    let mut names = explicit_protocol_refs(text);
    for bt in backtick_re().captures_iter(text) {
        if let Some(m) = bt.get(1) {
            names.insert(m.as_str().to_string());
        }
    }
    for caps in relative_link_re().captures_iter(text) {
        let target = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if target.starts_with("http:")
            || target.starts_with("https:")
            || target.starts_with("mailto:")
            || target.starts_with('#')
            || target.starts_with('/')
            || target.starts_with("../")
            || target.contains(':')
        {
            continue;
        }
        let base = target.rsplit('/').next().unwrap_or(target);
        let stem = match base.rsplit_once('.') {
            Some((s, _)) if !s.is_empty() => s,
            _ => base,
        };
        names.insert(stem.to_string());
    }
    for w in deferred_words(text) {
        names.insert(w);
    }
    names.into_iter().filter(|n| is_valid_name(n)).collect()
}

pub fn protocol_closure<T, E, R, F>(
    text: &str,
    mut resolve: R,
    mut read: F,
) -> Result<BTreeMap<String, T>, E>
where
    R: FnMut(&str) -> Option<T>,
    F: FnMut(&T) -> Result<String, E>,
{
    let mut found: BTreeMap<String, T> = BTreeMap::new();
    let mut pending: Vec<String> = vec![text.to_string()];
    while let Some(doc_text) = pending.pop() {
        let mentions = protocol_mentions(&doc_text);
        for name in mentions {
            if found.contains_key(&name) {
                continue;
            }
            if let Some(doc) = resolve(&name) {
                let body = read(&doc)?;
                found.insert(name, doc);
                pending.push(body);
            }
        }
    }
    Ok(found)
}

pub fn deferred_declared(body: &str) -> Vec<String> {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    for caps in deferred_re().captures_iter(body) {
        let para = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for bt in backtick_re().captures_iter(para) {
            if let Some(m) = bt.get(1) {
                refs.insert(m.as_str().to_string());
            }
        }
        for stem in bare_md_stems(para) {
            refs.insert(stem);
        }
    }
    refs.into_iter().collect()
}
