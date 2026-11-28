//! Native Rust port of `open_fleet/solo_review.py`:
//! honest, build-blind solo-developer review lane using in-process `diff_scope` + `of_floor`.

use crate::diff_scope::scope_to_json;
use chrono::Utc;
use of_common::gitexec::run_git_repo;
use of_floor::{evaluate as eval_floor, FloorConfig};
use of_install::{which, HARNESS_PROFILES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SCHEMA_VERSION: &str = "open-fleet-solo-review/v1";
const LIT_REQUIRED_FLAGS: &[&str] = &["AUTH", "SECURITY", "MIGRATIONS"];
const RISK_LENS_FLAGS: &[&str] = &["SECURITY", "AUTH", "PERF", "A11Y", "MIGRATIONS"];

struct GitMeta {
    head_sha: String,
    tree_sha: String,
    base_sha: String,
    changed_files: Vec<String>,
    diff_stat: String,
}

fn git_info(repo: &Path, base: &str) -> GitMeta {
    let run_s = |args: &[&str]| -> String {
        run_git_repo(repo, args, &[])
            .ok()
            .filter(|o| o.code == 0)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let base_spec = format!("{base}^{{commit}}");
    let range = format!("{base}...HEAD");
    let files_raw = run_s(&["diff", "--name-only", "--no-renames", &range]);
    let changed_files: Vec<String> = files_raw
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    GitMeta {
        head_sha: run_s(&["rev-parse", "HEAD"]),
        tree_sha: run_s(&["rev-parse", "HEAD^{tree}"]),
        base_sha: run_s(&["rev-parse", &base_spec]),
        changed_files,
        diff_stat: run_s(&["diff", "--stat", &range]),
    }
}

fn harness_binary(id: &str) -> &'static str {
    match id {
        "claude" => "claude",
        "codex" => "codex",
        "gemini" => "gemini",
        "opencode" => "opencode",
        "cursor" => "cursor",
        "antigravity" => "agy",
        _ => "",
    }
}

fn cross_model_reviewers(builder_harness: &str) -> Vec<Value> {
    let builder = builder_harness.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    for h in HARNESS_PROFILES {
        if h.id == builder {
            continue;
        }
        let binary = harness_binary(h.id);
        if binary.is_empty() {
            continue;
        }
        let Some(path) = which(binary) else {
            continue;
        };
        let cmd = match h.id {
            "codex" => "codex exec --sandbox read-only - < solo-review-prompt.md".to_string(),
            "claude" => "claude -p --permission-mode plan < solo-review-prompt.md".to_string(),
            "gemini" => "gemini -p \"$(cat solo-review-prompt.md)\"".to_string(),
            "opencode" => "opencode run \"$(cat solo-review-prompt.md)\"".to_string(),
            _ => format!("{binary} < solo-review-prompt.md"),
        };
        out.push(json!({
            "harness": h.id,
            "binary": binary,
            "path": path.display().to_string(),
            "command": cmd,
        }));
    }
    out
}

fn build_blind_prompt(
    base: &str,
    git_meta: &GitMeta,
    criteria_text: &str,
    contract_digest: &str,
    triggered_lenses: &[&str],
    floor_ok: bool,
) -> String {
    let lenses_str = if triggered_lenses.is_empty() {
        "none (acceptance axes only)".to_string()
    } else {
        triggered_lenses.join(", ")
    };
    let files_str = if git_meta.changed_files.is_empty() {
        "  - (working-tree or empty range)".to_string()
    } else {
        git_meta
            .changed_files
            .iter()
            .take(60)
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let criteria_block = if criteria_text.trim().is_empty() {
        "(No frozen contract file supplied — judge against the repo's tests, contracts, and diff scope.)"
    } else {
        criteria_text.trim()
    };
    let base_sha = if git_meta.base_sha.is_empty() {
        "unknown"
    } else {
        &git_meta.base_sha
    };
    let head_sha = if git_meta.head_sha.is_empty() {
        "unknown"
    } else {
        &git_meta.head_sha
    };
    let tree_sha = if git_meta.tree_sha.is_empty() {
        "unknown"
    } else {
        &git_meta.tree_sha
    };
    let digest_show = if contract_digest.is_empty() {
        "none"
    } else {
        contract_digest
    };
    let diff_base = if git_meta.base_sha.is_empty() {
        base
    } else {
        &git_meta.base_sha
    };
    let diff_head = if git_meta.head_sha.is_empty() {
        "HEAD"
    } else {
        &git_meta.head_sha
    };
    format!(
        "# Build-Blind Solo Acceptance Review Packet\n\n\
You are an independent, read-only reviewer in a FRESH session. Do NOT edit files.\n\
Builder narration has been deliberately stripped to prevent anchoring.\n\n\
- **Base ref / SHA:** `{base}` (`{base_sha}`)\n\
- **Pinned `reviewed_sha`:** `{head_sha}` (tree `{tree_sha}`)\n\
- **Contract digest:** `{digest_show}`\n\
- **Floor guard status:** `{}`\n\
- **Triggered risk lenses:** {lenses_str}\n\n\
## Frozen Acceptance Criteria\n\n\
{criteria_block}\n\n\
## Changed Files (`git diff --name-only <base>...HEAD`)\n\n\
{files_str}\n\n\
## Mandatory Protocol (`playbooks/acceptance-review.md`)\n\n\
1. **Blind-fix first (anti-anchoring):** BEFORE inspecting the diff, write 3–5 bullets stating where you expect the change to live, its shape, and your confidence.\n\
2. **Inspect the exact diff:** Run `git diff {diff_base}...{diff_head}`.\n\
3. **Three isolated axes (no cross-rerank):**\n   \
- **Standards:** repo conventions + code smells (skip what linters already enforce).\n   \
- **Spec:** every criterion met? Any scope creep or missing edge case?\n   \
- **Test-adequacy:** would reverting the production change fail a test?\n\
4. **Anti-false-positive gate:** Every Critical/Required finding MUST quote its verbatim motivating code line (`path:line`). Findings without a quoted line go to an appendix.\n\
5. **Verdict (under 400 words):** Emit `GO` (0 Critical, 0 Required) or `NO-GO`, bound explicitly to `reviewed_sha={diff_head}`.\n",
        if floor_ok {
            "CLEAN"
        } else {
            "VIOLATION — BLOCKING"
        }
    )
}

pub struct SoloReviewArgs {
    pub base: String,
    pub root: PathBuf,
    pub repo: PathBuf,
    pub contract_path: String,
    pub builder_harness: String,
    pub manifest: String,
    pub lighting: String,
    pub nc_command: String,
    pub no_gh: bool,
    pub transcript_out: String,
    pub transcript_key: String,
    pub packet_out: String,
}

pub fn run_solo_review(args: &SoloReviewArgs) -> Result<Value, String> {
    let base_ref = args.base.trim();
    if base_ref.is_empty() {
        return Err(
            "base ref is required (e.g. origin/main or an integration BASE branch)".to_string(),
        );
    }

    // 1. Native in-process diff_scope
    let (ds_code, scope_data) = scope_to_json(&args.repo, Some(base_ref), false);
    let flags_obj = scope_data.get("flags").and_then(|v| v.as_object());
    let flag_true = |f: &str| {
        flags_obj
            .and_then(|m| m.get(f))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let triggered_lenses: Vec<&str> = RISK_LENS_FLAGS
        .iter()
        .copied()
        .filter(|&f| flag_true(f))
        .collect();
    let lit_triggers: Vec<&str> = LIT_REQUIRED_FLAGS
        .iter()
        .copied()
        .filter(|&f| flag_true(f))
        .collect();

    // 2. Native in-process floor_guard
    let fg = eval_floor(&FloorConfig {
        base: Some(base_ref.to_string()),
        constraints: "CONSTRAINTS.md".to_string(),
        waivers: "docs/DECISIONS.md".to_string(),
        repo: args.repo.clone(),
        quiet: true,
        json: true,
    });
    let floor_ok = fg.exit_code == 0;
    let floor_output = if fg.findings.is_empty() {
        if floor_ok {
            "floor-guard: clean".to_string()
        } else {
            fg.status.clone()
        }
    } else {
        fg.findings
            .iter()
            .map(|f| format!("{}:{}: {} ({})", f.path, f.line, f.rule, f.detail))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // 3. Git metadata + optional frozen contract digest
    let git_meta = git_info(&args.repo, base_ref);
    let mut criteria_text = String::new();
    let mut contract_digest = String::new();
    if !args.contract_path.trim().is_empty() {
        let raw_p = PathBuf::from(args.contract_path.trim());
        let cpath = if raw_p.is_absolute() {
            raw_p
        } else {
            args.repo.join(raw_p)
        };
        if !cpath.is_file() {
            return Err(format!("contract file not found: {}", cpath.display()));
        }
        let raw_bytes =
            fs::read(&cpath).map_err(|e| format!("cannot read {}: {e}", cpath.display()))?;
        contract_digest = format!("sha256:{}", hex::encode(Sha256::digest(&raw_bytes)));
        criteria_text = String::from_utf8_lossy(&raw_bytes).into_owned();
    }

    // 4. Honest lighting eligibility
    let scope_err = scope_data.get("error").and_then(|v| v.as_str());
    let scope_ok = ds_code == 0 && scope_err.is_none();
    let has_nc = !args.nc_command.trim().is_empty();
    let dark_eligible = scope_ok && lit_triggers.is_empty() && has_nc;
    let requested = {
        let l = args.lighting.trim().to_ascii_lowercase();
        if l.is_empty() {
            "auto".to_string()
        } else {
            l
        }
    };
    if !matches!(requested.as_str(), "auto" | "lit" | "dark-eligible") {
        return Err(format!(
            "invalid lighting {:?}; choose auto, lit, or dark-eligible",
            args.lighting
        ));
    }
    if requested == "dark-eligible" && (!scope_ok || !lit_triggers.is_empty()) {
        let why = if !lit_triggers.is_empty() {
            format!(
                "diff touches lit-required surfaces ({})",
                lit_triggers.join(", ")
            )
        } else {
            format!("diff_scope failed ({})", scope_err.unwrap_or("unknown"))
        };
        return Err(format!(
            "cannot use --lighting dark-eligible: {why} — independent review cannot be waived"
        ));
    }
    if requested == "dark-eligible" && !has_nc {
        return Err(
            "--lighting dark-eligible requires --nc-command (an unfakeable executed negative control)"
                .to_string(),
        );
    }

    let effective_lighting =
        if requested == "dark-eligible" || (requested == "auto" && dark_eligible) {
            "dark-eligible"
        } else {
            "lit"
        };
    let eligibility_reason = if !lit_triggers.is_empty() {
        format!(
            "Diff touches lit-required surface ({}). Dark-eligible review waiver is forbidden; run a fresh cross-model or human reviewer before merge.",
            lit_triggers.join(", ")
        )
    } else if !scope_ok {
        "diff_scope did not succeed; failing closed to lit review mode.".to_string()
    } else if has_nc {
        "Diff is off the irreversibility stop-list (no AUTH/SECURITY/MIGRATIONS) and carries an executed negative-control command: eligible for solo Lane-A `--lighting dark-eligible --execute-nc`.".to_string()
    } else {
        "Diff is off the irreversibility stop-list, but no `--nc-command` was provided; provide `--nc-command` for Lane-A executed-control verification or dispatch a fresh cross-model reviewer.".to_string()
    };

    let blind_prompt = build_blind_prompt(
        base_ref,
        &git_meta,
        &criteria_text,
        &contract_digest,
        &triggered_lenses,
        floor_ok,
    );
    if !args.packet_out.trim().is_empty() {
        let p_out = PathBuf::from(args.packet_out.trim());
        if let Some(parent) = p_out.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        fs::write(&p_out, &blind_prompt).map_err(|e| e.to_string())?;
    }

    // 5. Optional independent native `open-fleet verify` invocation
    let mut verify_result: Value = Value::Null;
    let mut verify_ok = true;
    let review_mode: &str;
    if !args.manifest.trim().is_empty() {
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("open-fleet"));
        let mut cmd_args = vec![
            "verify".to_string(),
            "--manifest".to_string(),
            args.manifest.trim().to_string(),
            "--base".to_string(),
            base_ref.to_string(),
            "--lighting".to_string(),
            effective_lighting.to_string(),
        ];
        if effective_lighting == "dark-eligible" {
            cmd_args.extend([
                "--lane".to_string(),
                "A".to_string(),
                "--execute-nc".to_string(),
                "--nc-command".to_string(),
                args.nc_command.trim().to_string(),
            ]);
            review_mode = "solo-dark-eligible-executed-nc";
        } else {
            review_mode = if args.no_gh {
                "solo-no-gh-lit"
            } else {
                "solo-lit-github-required"
            };
            if has_nc {
                cmd_args.extend([
                    "--execute-nc".to_string(),
                    "--nc-command".to_string(),
                    args.nc_command.trim().to_string(),
                ]);
            }
        }
        if args.no_gh {
            cmd_args.push("--no-gh".to_string());
        }
        if !args.contract_path.trim().is_empty() && !contract_digest.is_empty() {
            cmd_args.extend([
                "--contract-source".to_string(),
                args.contract_path.trim().to_string(),
                "--contract-digest".to_string(),
                contract_digest.clone(),
            ]);
        }
        if !args.transcript_out.trim().is_empty() {
            cmd_args.extend([
                "--transcript-out".to_string(),
                args.transcript_out.trim().to_string(),
            ]);
        }
        if !args.transcript_key.trim().is_empty() {
            cmd_args.extend([
                "--transcript-key".to_string(),
                args.transcript_key.trim().to_string(),
            ]);
        }
        let out = Command::new(exe)
            .args(&cmd_args)
            .current_dir(&args.repo)
            .env("OPEN_FLEET_ROOT", &args.root)
            .stdin(Stdio::null())
            .output();
        verify_result = match out {
            Ok(o) => {
                let code = o.status.code().unwrap_or(1);
                verify_ok = code == 0;
                json!({
                    "ok": verify_ok,
                    "returncode": code,
                    "stdout": String::from_utf8_lossy(&o.stdout).into_owned(),
                    "stderr": String::from_utf8_lossy(&o.stderr).into_owned(),
                })
            }
            Err(err) => {
                verify_ok = false;
                json!({
                    "ok": false,
                    "returncode": 127,
                    "stdout": "",
                    "stderr": err.to_string(),
                })
            }
        };
    } else if effective_lighting == "dark-eligible" {
        review_mode = "solo-dark-eligible-ready";
    } else {
        review_mode = "solo-lit-packet-only";
    }

    let overall_ok = scope_ok && floor_ok && verify_ok;
    Ok(json!({
        "schema_version": SCHEMA_VERSION,
        "ts": Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "ok": overall_ok,
        "review_mode": review_mode,
        "base": base_ref,
        "git": {
            "head_sha": git_meta.head_sha,
            "tree_sha": git_meta.tree_sha,
            "base_sha": git_meta.base_sha,
            "changed_files": git_meta.changed_files,
            "diff_stat": git_meta.diff_stat,
        },
        "diff_scope": {
            "ok": scope_ok,
            "error": scope_err,
            "flags": scope_data.get("flags").cloned().unwrap_or_else(|| json!({})),
            "unmatched": scope_data.get("unmatched").cloned().unwrap_or_else(|| json!([])),
            "triggered_risk_lenses": triggered_lenses,
            "lit_required_triggers": lit_triggers,
        },
        "floor_guard": {
            "ok": floor_ok,
            "returncode": fg.exit_code,
            "output": floor_output,
        },
        "lighting": {
            "requested": requested,
            "effective": effective_lighting,
            "dark_eligible": dark_eligible,
            "reason": eligibility_reason,
        },
        "contract_digest": contract_digest,
        "cross_model_reviewers": cross_model_reviewers(&args.builder_harness),
        "blind_review_packet": blind_prompt,
        "packet_out": if args.packet_out.trim().is_empty() { Value::Null } else { json!(args.packet_out.trim()) },
        "verify": verify_result,
    }))
}
