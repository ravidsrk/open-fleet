//! Control-outcome reader — native Rust port of `runtime/scripts/_verify_sig.py`.
//! Distinguishes genuine assertion failures from stillborn mutants / runner load errors (#280, #768).

use regex::Regex;
use std::sync::OnceLock;

const STILLBORN_MARKERS: &[&str] = &[
    "importerror",
    "modulenotfounderror",
    "syntaxerror",
    "indentationerror",
    "cannot import name",
    "error collecting",
    "collection error",
    "unable to import",
    "no module named",
    "failed to load",
    "conftest.py",
    "attributeerror: module",
    "cannot find module",
    "could not compile",
];

const ASSERTION_MARKERS: &[&str] = &[
    "assertionerror",
    "assert",
    "failed",
    "fail:",
    "failures=",
    "expected",
    "not ok",
    "panicked at",
    "✗",
    "test failed",
    "e   ",
    "✕",
];

fn ansi_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))").expect("regex")
    })
}

fn strong_assertion_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?m)^[ \t]*(?:e[ \t]+)?assertionerror\b",
            r"|^[ \t]*e[ \t]+assert\b",
            r"|^[ \t]*e[ \t]+failed: did not raise\b",
            r"|^[ \t]*thread .*panicked at",
        ))
        .expect("regex")
    })
}

fn stillborn_shape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?m)^[ \t]*(?:e[ \t]+)?(?:syntaxerror|indentationerror|taberror|importerror|modulenotfounderror)\b",
            r"|^[ \t]*(?:e[ \t]+)?attributeerror: module\b",
            r#"|^failed \S+ - +(?:file "|(?:syntaxerror|importerror|modulenotfounderror)\b)"#,
            r"|^[ \t]*(?:error: )?cannot find module\b",
            r"|●[ \t]*test suite failed to run",
            r"|^\W*failed suites \d+",
            r"|^[ \t]*(?:error: )?failed to (?:load url|resolve import)\b",
            r"|^[_= \t]*errors? collecting\b|\berrors? during collection\b",
            r"|\[(?:build|setup) failed\]",
            r"|^error: could not compile\b",
        ))
        .expect("regex")
    })
}

fn errors_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\berrors?\s*[=:]\s*(\d+)|\b(\d+)\s+errors?\b").expect("regex"))
}

fn failures_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bfailures?\s*[=:]\s*(\d+)|\b(\d+)\s+failed\b").expect("regex"))
}

pub fn counted(pattern: &Regex, text: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut seen = false;
    for caps in pattern.captures_iter(text) {
        for idx in 1..caps.len() {
            if let Some(m) = caps.get(idx) {
                if let Ok(n) = m.as_str().parse::<u64>() {
                    total += n;
                    seen = true;
                }
            }
        }
    }
    if seen {
        Some(total)
    } else {
        None
    }
}

pub fn failure_signature(out: &str, err: &str) -> (bool, Option<String>) {
    let combined = format!("{out}\n{err}");
    let stripped = ansi_re().replace_all(&combined, "");
    let text = stripped.to_lowercase();
    if text.trim().is_empty() {
        return (
            false,
            Some(
                "the control run produced NO output at all. A silent non-zero exit is not a \
                 failing test — it is what `grep` does when it finds nothing; fail-closed (#280)"
                    .to_string(),
            ),
        );
    }
    let errors = counted(errors_re(), &text);
    let failures = counted(failures_re(), &text);
    if errors.unwrap_or(0) > 0 && failures.unwrap_or(0) == 0 {
        return (
            false,
            Some(format!(
                "the runner reports {} error(s) and no assertion failure — an error is \
                 an exception escaping, not an oracle evaluating to false, so it does not \
                 show the criterion-bound assertion ran at all; fail-closed (#280)",
                errors.unwrap_or(0)
            )),
        );
    }
    if let Some(shape) = stillborn_shape_re().find(&text) {
        let counted_msg = match failures {
            Some(n) if n > 0 => format!(" beside {n} counted failure(s)"),
            _ => String::new(),
        };
        return (
            false,
            Some(format!(
                "the control run reports a load failure ({:?}){} \
                 — that is a STILLBORN MUTANT, not a kill. A module that fails to load, or \
                 a suite that never ran, makes every command that touches it exit non-zero; \
                 a failed count or an assertion failing elsewhere in the same run does not \
                 show the criterion-bound oracle ran. The control must leave the code \
                 loadable and fail an ASSERTION (#280; 2026-10-23 review, P1-1)",
                shape.as_str().trim(),
                counted_msg
            )),
        );
    }
    let stillborn: Vec<&str> = STILLBORN_MARKERS
        .iter()
        .copied()
        .filter(|m| text.contains(m))
        .collect();
    if !stillborn.is_empty() && !strong_assertion_re().is_match(&text) {
        return (
            false,
            Some(format!(
                "the control run did not get as far as an oracle ({:?} in \
                 its output, and nothing showing an assertion was evaluated) — that is \
                 a STILLBORN MUTANT, not a kill. The non-zero exit is the module failing \
                 to load, which would happen for any command; the control must leave the \
                 code runnable and fail an ASSERTION (#280)",
                stillborn[0]
            )),
        );
    }
    if !ASSERTION_MARKERS.iter().any(|m| text.contains(m)) {
        return (
            false,
            Some(
                "the control run exited non-zero but its output names no assertion failure, \
                 so nothing shows the criterion-bound oracle actually ran and failed; \
                 fail-closed (#280)"
                    .to_string(),
            ),
        );
    }
    (true, None)
}
