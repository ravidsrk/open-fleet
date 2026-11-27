//! Hunk-counted unified-diff records, mirroring `runtime/scripts/diffparse.py`.
//!
//! Splits on `\n` ONLY (never `\r` or Unicode separators), and counts old/new lines declared by
//! each `@@ -a,b +c,d @@` header so content lines beginning with `-- ` or `++ ` cannot spoof
//! diff file headers.

use regex::Regex;
use std::sync::OnceLock;

pub const NO_NEWLINE: &str = "\\ No newline at end of file";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffRecord<'a> {
    Header(&'a str),
    Hunk {
        line: &'a str,
        old_start: usize,
        old_count: usize,
        new_start: usize,
        new_count: usize,
    },
    Added(&'a str),
    Removed(&'a str),
    Context(&'a str),
    Marker(&'a str),
}

fn hunk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").expect("valid hunk regex")
    })
}

pub fn records(diff_text: &str) -> Result<Vec<DiffRecord<'_>>, String> {
    let mut out = Vec::new();
    let mut old_left: isize = 0;
    let mut new_left: isize = 0;

    for line in diff_text.split('\n') {
        if line == NO_NEWLINE {
            out.push(DiffRecord::Marker(line));
            continue;
        }
        if old_left != 0 || new_left != 0 {
            let first = line.as_bytes().first().copied();
            match first {
                Some(b'-') => {
                    old_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    out.push(DiffRecord::Removed(line));
                }
                Some(b'+') => {
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    out.push(DiffRecord::Added(line));
                }
                Some(b' ') => {
                    old_left -= 1;
                    new_left -= 1;
                    if old_left < 0 || new_left < 0 {
                        return Err("diff hunk exceeds declared line counts".to_string());
                    }
                    out.push(DiffRecord::Context(line));
                }
                _ => {
                    return Err("incomplete diff hunk".to_string());
                }
            }
        } else if line.starts_with("@@") {
            let caps = hunk_re()
                .captures(line)
                .ok_or_else(|| "malformed hunk header".to_string())?;
            let old_start: usize = caps[1]
                .parse()
                .map_err(|_| "malformed hunk header".to_string())?;
            let old_count: usize = caps
                .get(2)
                .map(|m| m.as_str().parse())
                .transpose()
                .map_err(|_| "malformed hunk header".to_string())?
                .unwrap_or(1);
            let new_start: usize = caps[3]
                .parse()
                .map_err(|_| "malformed hunk header".to_string())?;
            let new_count: usize = caps
                .get(4)
                .map(|m| m.as_str().parse())
                .transpose()
                .map_err(|_| "malformed hunk header".to_string())?
                .unwrap_or(1);
            old_left = old_count as isize;
            new_left = new_count as isize;
            out.push(DiffRecord::Hunk {
                line,
                old_start,
                old_count,
                new_start,
                new_count,
            });
        } else {
            out.push(DiffRecord::Header(line));
        }
    }

    if old_left != 0 || new_left != 0 {
        return Err("incomplete diff hunk".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_starting_with_dashes_stays_content() {
        let diff =
            "--- a/.coveragerc\n+++ b/.coveragerc\n@@ -1,2 +1,1 @@\n--- note\n fail_under = 80\n";
        let recs = records(diff).expect("valid diff");
        assert!(matches!(recs[3], DiffRecord::Removed("--- note")));
        assert!(matches!(recs[4], DiffRecord::Context(" fail_under = 80")));
    }

    #[test]
    fn truncated_hunk_fails_closed() {
        let diff = "@@ -1,2 +1,0 @@\n-only one\n";
        assert!(records(diff).is_err());
    }
}
