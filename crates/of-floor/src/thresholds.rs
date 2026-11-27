//! Constraints-row key extraction, Unicode NFKC folding, and threshold-lowering detection,
//! mirroring `runtime/scripts/floor_guard.py:526-718`.

use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

fn nfkc(s: &str) -> String {
    s.nfkc().collect()
}

fn not_a_threshold_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}(?:T[\d:]+Z?)?|#\d+|\b[A-Z]+\d+(?:[.-][A-Za-z0-9]+)*")
            .expect("regex")
    })
}

fn number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+(?:\.\d+)?").expect("regex"))
}

fn number_unit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\d+(?:\.\d+)?)\s?(%|[A-Za-z]+)?").expect("regex"))
}

fn floor_words_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)>=|<=|≥|≤|\bfloor\b|\bthreshold\b|\beffective\b|\bminimum\b|\bat least\b|\bno (?:lower|less|fewer)\b",
        )
        .expect("regex")
    })
}

fn comparator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r">=|<=|≥|≤|>|<").expect("regex"))
}

fn comparator_numeric_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:>=|<=|≥|≤|>|<)\s*=?\s*\d").expect("regex"))
}

fn comparator_number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:>=|<=|≥|≤|>|<)\s*=?\s*(\d+(?:\.\d+)?)").expect("regex"))
}

fn row_bullet_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[-*#\s]*([A-Za-z0-9_.][A-Za-z0-9_.-]*)").expect("regex"))
}

pub fn is_constraints(path: &str, constraints_name: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let a = Path::new(path).file_name();
    let b = Path::new(constraints_name).file_name();
    a.is_some() && a == b
}

/// Format float identically to Python's `{v:g}` (6 significant digits, trimming trailing zeros).
pub fn fmt_g(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e6 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.6}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    trimmed.to_string()
}

fn count_ge_comp(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '≥' {
            count += 1;
            i += 1;
        } else if chars[i] == '>' && i + 1 < chars.len() && chars[i + 1] == '=' {
            count += 1;
            i += 2;
        } else if chars[i] == '>' {
            let prev_bad = i > 0 && matches!(chars[i - 1], '-' | '<' | '>' | '=' | '≤' | '≥');
            let next_bad = i + 1 < chars.len() && chars[i + 1] == '=';
            if !prev_bad && !next_bad {
                count += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    count
}

fn count_le_comp(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '≤' {
            count += 1;
            i += 1;
        } else if chars[i] == '<' && i + 1 < chars.len() && chars[i + 1] == '=' {
            count += 1;
            i += 2;
        } else if chars[i] == '<' {
            let prev_bad = i > 0 && matches!(chars[i - 1], '<' | '>' | '=' | '≤' | '≥');
            let next_bad = i + 1 < chars.len() && matches!(chars[i + 1], '=' | '-');
            if !prev_bad && !next_bad {
                count += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    count
}

fn comparator_flipped(bcell: &str, acell: &str) -> bool {
    let b_ge = count_ge_comp(bcell);
    let a_ge = count_ge_comp(acell);
    let b_le = count_le_comp(bcell);
    let a_le = count_le_comp(acell);
    b_ge > 0 && a_ge < b_ge && a_le > b_le
}

fn comparator_numbers(text: &str) -> Vec<f64> {
    let folded = nfkc(text);
    let cleaned = not_a_threshold_re().replace_all(&folded, " ");
    comparator_number_re()
        .captures_iter(&cleaned)
        .filter_map(|c| c[1].parse::<f64>().ok())
        .collect()
}

pub fn numbers(text: &str) -> Vec<f64> {
    let folded = nfkc(text);
    let cleaned = not_a_threshold_re().replace_all(&folded, " ");
    number_re()
        .find_iter(&cleaned)
        .filter_map(|m| m.as_str().parse::<f64>().ok())
        .collect()
}

pub fn numbers_with_units(text: &str) -> Vec<(f64, String)> {
    let folded = nfkc(text);
    let cleaned = not_a_threshold_re().replace_all(&folded, " ");
    number_unit_re()
        .captures_iter(&cleaned)
        .filter_map(|c| {
            let val = c[1].parse::<f64>().ok()?;
            let unit = c
                .get(2)
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_default();
            Some((val, unit))
        })
        .collect()
}

pub fn cells(text: &str) -> Vec<String> {
    let folded = nfkc(text);
    let trimmed = folded.trim();
    if trimmed.starts_with('|') {
        trimmed
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect()
    } else {
        vec![trimmed.to_string()]
    }
}

pub fn row_key(text: &str) -> String {
    let folded = nfkc(text);
    let trimmed = folded.trim();
    if !trimmed.starts_with('|') {
        return row_bullet_key_re()
            .captures(trimmed)
            .map(|c| c[1].to_ascii_lowercase())
            .unwrap_or_default();
    }
    for token in trimmed.split('|') {
        let cleaned = token
            .trim()
            .trim_matches(['-', '*', '#', ' '])
            .to_ascii_lowercase();
        if !cleaned.is_empty() {
            return cleaned;
        }
    }
    String::new()
}

pub fn shape_key(text: &str) -> String {
    let key = row_key(text);
    if key.is_empty() {
        return String::new();
    }
    if text.trim().starts_with('|') {
        format!("row:{key}")
    } else {
        format!("line:{key}")
    }
}

pub fn lowering(before_text: &str, after_text: &str) -> Option<String> {
    let b_cells = cells(before_text);
    let a_cells = cells(after_text);

    if b_cells.len() == 1 && a_cells.len() == 1 {
        let bcell = &b_cells[0];
        let acell = &a_cells[0];
        let b_units = numbers_with_units(bcell);
        let a_units = numbers_with_units(acell);
        let before: Vec<f64> = b_units.iter().map(|(v, _)| *v).collect();
        let after: Vec<f64> = a_units.iter().map(|(v, _)| *v).collect();
        if comparator_flipped(bcell, acell) {
            return Some("comparator direction flipped".to_string());
        }
        if !before.is_empty()
            && comparator_re().is_match(bcell)
            && !comparator_numeric_re().is_match(acell)
        {
            return Some("criterion no longer compares against a number".to_string());
        }
        let gone: Vec<(f64, String)> = b_units
            .iter()
            .filter(|(v, _)| !after.contains(v))
            .cloned()
            .collect();
        let fresh: Vec<(f64, String)> = a_units
            .iter()
            .filter(|(v, _)| !before.contains(v))
            .cloned()
            .collect();
        if gone.is_empty() {
            if !fresh.is_empty() {
                let a_comp: Vec<f64> = comparator_numbers(acell)
                    .into_iter()
                    .filter(|v| !before.contains(v))
                    .collect();
                for (old, unit) in &b_units {
                    for &new in &a_comp {
                        if new < *old {
                            return Some(format!("{} -> {}", fmt_g(*old), fmt_g(new)));
                        }
                    }
                    let same_unit: Vec<f64> = fresh
                        .iter()
                        .filter(|(new, u)| u == unit && *new < *old)
                        .map(|(new, _)| *new)
                        .collect();
                    if !same_unit.is_empty()
                        && (!unit.is_empty()
                            || floor_words_re().is_match(acell)
                            || comparator_re().is_match(acell))
                    {
                        let min_v = same_unit.iter().copied().fold(f64::INFINITY, f64::min);
                        return Some(format!("{} -> {}", fmt_g(*old), fmt_g(min_v)));
                    }
                }
            }
            return None;
        }
        if fresh.is_empty() {
            return Some(format!("{} -> (no number)", fmt_g(gone[0].0)));
        }
        if fresh.len() == gone.len() {
            for ((old, _), (new, _)) in gone.iter().zip(fresh.iter()) {
                if new < old {
                    return Some(format!("{} -> {}", fmt_g(*old), fmt_g(*new)));
                }
            }
            return None;
        }
        for (old, unit) in &gone {
            let same: Vec<f64> = fresh
                .iter()
                .filter(|(_, u)| u == unit)
                .map(|(v, _)| *v)
                .collect();
            let candidates: Vec<f64> = if !same.is_empty() {
                same
            } else {
                fresh.iter().map(|(v, _)| *v).collect()
            };
            let lower: Vec<f64> = candidates.into_iter().filter(|new| new < old).collect();
            if !lower.is_empty() {
                let max_l = lower.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                return Some(format!("{} -> {}", fmt_g(*old), fmt_g(max_l)));
            }
        }
        let a_comp: Vec<f64> = comparator_numbers(acell)
            .into_iter()
            .filter(|v| !before.contains(v))
            .collect();
        for (old, unit) in &b_units {
            for &new in &a_comp {
                if new < *old {
                    return Some(format!("{} -> {}", fmt_g(*old), fmt_g(new)));
                }
            }
            let same_unit: Vec<f64> = fresh
                .iter()
                .filter(|(new, u)| u == unit && *new < *old)
                .map(|(new, _)| *new)
                .collect();
            if !same_unit.is_empty()
                && (!unit.is_empty()
                    || floor_words_re().is_match(acell)
                    || comparator_re().is_match(acell))
            {
                let min_v = same_unit.iter().copied().fold(f64::INFINITY, f64::min);
                return Some(format!("{} -> {}", fmt_g(*old), fmt_g(min_v)));
            }
        }
        return None;
    }

    for (i, bcell) in b_cells.iter().enumerate() {
        let acell = a_cells.get(i).map(|s| s.as_str()).unwrap_or("");
        if comparator_flipped(bcell, acell) {
            return Some("comparator direction flipped".to_string());
        }
        let before = numbers(bcell);
        let after = numbers(acell);
        for (j, &value) in before.iter().enumerate() {
            if j >= after.len() {
                return Some(format!("{} -> (no number)", fmt_g(value)));
            }
            if after[j] < value {
                return Some(format!("{} -> {}", fmt_g(value), fmt_g(after[j])));
            }
        }
        if !before.is_empty()
            && comparator_re().is_match(bcell)
            && !comparator_numeric_re().is_match(acell)
        {
            return Some("criterion no longer compares against a number".to_string());
        }
        if after.len() > before.len()
            && (floor_words_re().is_match(acell) || comparator_re().is_match(acell))
        {
            return Some(format!(
                "a floor-shaped number was added: {}",
                fmt_g(after[before.len()])
            ));
        }
        if after.len() > before.len() && !before.is_empty() {
            let b_units = numbers_with_units(bcell);
            let a_units = numbers_with_units(acell);
            let fresh: Vec<(f64, String)> = a_units
                .into_iter()
                .filter(|(v, _)| !before.contains(v))
                .collect();
            for (old, unit) in &b_units {
                if unit.is_empty() {
                    continue;
                }
                let same: Vec<f64> = fresh
                    .iter()
                    .filter(|(new, u)| u == unit && *new < *old)
                    .map(|(new, _)| *new)
                    .collect();
                if !same.is_empty() {
                    let min_v = same.iter().copied().fold(f64::INFINITY, f64::min);
                    return Some(format!("{} -> {}", fmt_g(*old), fmt_g(min_v)));
                }
            }
        }
    }
    let extra_start = b_cells.len().min(a_cells.len());
    for acell in &a_cells[extra_start..] {
        let nums = numbers(acell);
        if !nums.is_empty() && (floor_words_re().is_match(acell) || comparator_re().is_match(acell))
        {
            return Some(format!(
                "a floor-shaped number was added: {}",
                fmt_g(nums[0])
            ));
        }
    }
    None
}
