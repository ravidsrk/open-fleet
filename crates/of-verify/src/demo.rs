//! Native zero-Python negative-control proof demo (`open-fleet demo`).
//!
//! Demonstrates head-to-head why a frozen denominator + independent re-derivation
//! catches scope-shrinking where a self-scoring gate goes GREEN:
//!   - Frozen spec defines two acceptance criteria: `AC-1` and `AC-2`.
//!   - A gamed unit manifest reports only `AC-1` (`PASS`), silently omitting `AC-2`.
//!   - Self-scorer grades only the worker's reported list -> GREEN (exit 0).
//!   - Independent `open-fleet verify` re-derives the frozen contract -> RED (exit 2),
//!     explicitly naming the dropped `AC-2` criterion.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FROZEN_SPEC: &str = "\
# Frozen contract (fixture)

- AC-1: the addressed criterion
- AC-2: the criterion a scope-shrink drops
";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn selfscore_manifest(manifest: &Value) -> (i32, String) {
    let criteria = manifest
        .get("criteria")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if criteria.is_empty() {
        return (1, "selfscore: RED — no criteria in manifest".to_string());
    }
    let all_pass = criteria
        .iter()
        .all(|c| c.get("addressed").and_then(Value::as_bool).unwrap_or(false));
    if all_pass {
        let ids: Vec<&str> = criteria
            .iter()
            .filter_map(|c| c.get("id").and_then(Value::as_str))
            .collect();
        (
            0,
            format!(
                "selfscore: GREEN — all {} self-reported criteria addressed ({})",
                ids.len(),
                ids.join(", ")
            ),
        )
    } else {
        (
            1,
            "selfscore: RED — a self-reported criterion failed".to_string(),
        )
    }
}

fn init_demo_repo(dir: &Path) -> Result<(String, PathBuf, PathBuf, String), String> {
    let git = of_common::gitexec::git_binary().map_err(|e| format!("git unavailable: {e}"))?;
    let run_git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new(git)
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "open-fleet demo")
            .env("GIT_AUTHOR_EMAIL", "demo@open-fleet.invalid")
            .env("GIT_COMMITTER_NAME", "open-fleet demo")
            .env("GIT_COMMITTER_EMAIL", "demo@open-fleet.invalid")
            .output()
            .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    run_git(&["init", "-q", "-b", "main"])?;
    let spec_rel = PathBuf::from("frozen-spec.md");
    let spec_path = dir.join(&spec_rel);
    fs::write(&spec_path, FROZEN_SPEC).map_err(|e| format!("write spec: {e}"))?;
    run_git(&["add", "frozen-spec.md"])?;
    run_git(&["commit", "-qm", "freeze spec (AC-1, AC-2)"])?;
    let head_sha = run_git(&["rev-parse", "HEAD"])?;
    let digest = format!("sha256:{}", sha256_hex(FROZEN_SPEC.as_bytes()));

    let manifest = json!({
        "unit": "review-it",
        "unit_class": "report-only",
        "base_sha": head_sha,
        "head_sha": head_sha,
        "contract": {
            "source": "frozen-spec.md",
            "digest": "",
            "criterion_ids": ["AC-1", "AC-2"]
        },
        "criteria": [
            {
                "id": "AC-1",
                "text": "the addressed one",
                "addressed": true
            }
        ],
        "pr": {
            "number": 0,
            "url": "",
            "reviewed_sha": head_sha
        },
        "claim": "done (AC-2 quietly dropped from the reported criteria — caught by frozen-source re-derivation)"
    });
    let manifest_path = dir.join("gamed-manifest.json");
    let rendered = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    fs::write(&manifest_path, format!("{rendered}\n"))
        .map_err(|e| format!("write manifest: {e}"))?;

    Ok((digest, spec_rel, manifest_path, head_sha))
}

fn find_open_fleet_binary() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("OPEN_FLEET_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        let name = exe
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name == "open-fleet" {
            return Some(exe);
        }
    }
    of_install::which("open-fleet")
}

/// Run the standalone zero-Python negative-control head-to-head demo.
pub fn run_negative_control_demo() -> Value {
    let tmp = match tempfile::Builder::new().prefix("of-demo-nc-").tempdir() {
        Ok(d) => d,
        Err(err) => {
            return json!({
                "ok": false,
                "returncode": 2,
                "engine": "rust",
                "self_score_green": false,
                "verifier_caught_gamed_manifest": false,
                "stdout": "",
                "stderr": format!("failed to create temp dir: {err}"),
            });
        }
    };

    let (digest, spec_rel, manifest_path, _head_sha) = match init_demo_repo(tmp.path()) {
        Ok(x) => x,
        Err(err) => {
            return json!({
                "ok": false,
                "returncode": 2,
                "engine": "rust",
                "self_score_green": false,
                "verifier_caught_gamed_manifest": false,
                "stdout": "",
                "stderr": err,
            });
        }
    };

    let manifest_val: Value = fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let (ss_rc, ss_msg) = selfscore_manifest(&manifest_val);

    let Some(bin) = find_open_fleet_binary() else {
        return json!({
            "ok": false,
            "returncode": 2,
            "engine": "rust",
            "self_score_green": ss_rc == 0,
            "verifier_caught_gamed_manifest": false,
            "stdout": ss_msg,
            "stderr": "could not locate open-fleet binary to execute native verify leg",
        });
    };

    let verify_out = Command::new(&bin)
        .args([
            "verify",
            "--manifest",
            &manifest_path.to_string_lossy(),
            "--contract-source",
            &spec_rel.to_string_lossy(),
            "--contract-digest",
            &digest,
            "--unit-class",
            "report-only",
            "--no-gh",
        ])
        .current_dir(tmp.path())
        .output();

    let (vf_rc, vf_stdout, vf_stderr) = match verify_out {
        Ok(out) => (
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(err) => (
            1,
            String::new(),
            format!("failed to run open-fleet verify: {err}"),
        ),
    };

    let combined = format!("{vf_stdout}\n{vf_stderr}");
    let scope_named = combined.contains("not addressed") && combined.contains("AC-2");
    let caught = ss_rc == 0 && vf_rc == 2 && scope_named;

    let mut report = String::new();
    report.push_str("### negative-control head-to-head (scope-shrink trap · native Rust engine)\n");
    report
        .push_str("### trap: frozen contract = [AC-1, AC-2]; worker self-reported only [AC-1]\n\n");
    report.push_str("== [1] SELF-SCORING gate (grades the self-reported criteria) ==\n");
    report.push_str(&format!("{ss_msg}\nself-scorer exit: {ss_rc}\n\n"));
    report.push_str(
        "== [2] open-fleet INDEPENDENT verifier (re-derives the frozen denominator) ==\n",
    );
    if !vf_stdout.trim().is_empty() {
        report.push_str(vf_stdout.trim());
        report.push('\n');
    }
    if !vf_stderr.trim().is_empty() {
        report.push_str(vf_stderr.trim());
        report.push('\n');
    }
    report.push_str(&format!(
        "open-fleet verify exit: {vf_rc}\n\n== verdict ==\n"
    ));
    if caught {
        report.push_str(&format!(
            "PASS: self-scorer GREEN (exit {ss_rc}) while open-fleet caught the dropped criterion AC-2 RED (exit {vf_rc}).\n"
        ));
        report.push_str(
            "The moat is the frozen denominator + independent re-derivation, not the gate mechanism.\n",
        );
    } else {
        report.push_str(&format!("UNEXPECTED: ss={ss_rc} vf={vf_rc}\n"));
    }

    json!({
        "ok": caught,
        "returncode": if caught { 0 } else { 1 },
        "engine": "rust",
        "self_score_green": ss_rc == 0,
        "verifier_caught_gamed_manifest": caught,
        "verifier_exit": vf_rc,
        "dropped_criterion": "AC-2",
        "stdout": report,
        "stderr": if caught { "" } else { vf_stderr.trim() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selfscore_accepts_gamed_single_criterion_manifest() {
        let m = json!({
            "criteria": [{"id": "AC-1", "text": "the addressed one", "addressed": true}]
        });
        let (rc, msg) = selfscore_manifest(&m);
        assert_eq!(rc, 0);
        assert!(msg.contains("selfscore: GREEN"));
        assert!(msg.contains("AC-1"));
    }

    #[test]
    fn demo_repo_fixture_freezes_two_criteria_and_digest() {
        let tmp = tempfile::Builder::new()
            .prefix("of-demo-unit-")
            .tempdir()
            .expect("tmp");
        let (digest, spec_rel, manifest_path, head_sha) =
            init_demo_repo(tmp.path()).expect("init_demo_repo");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 7 + 64);
        assert_eq!(spec_rel, PathBuf::from("frozen-spec.md"));
        assert!(manifest_path.is_file());
        assert_eq!(head_sha.len(), 40);
    }
}
