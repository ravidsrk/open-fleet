//! Native Rust port of `open_fleet/ci_action.py`:
//! composable PR verification runner using native `of_floor` + `diff_scope` + `verify`.

use crate::diff_scope::scope_to_json;
use of_floor::{evaluate as eval_floor, FloorConfig};
use serde_json::{json, Value};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const RISK_LENS_FLAGS: &[&str] = &["SECURITY", "AUTH", "MIGRATIONS", "PERF", "A11Y"];

pub struct CiCheckArgs {
    pub base: String,
    pub root: PathBuf,
    pub repo: PathBuf,
    pub run_floor_guard: bool,
    pub run_diff_scope: bool,
    pub strict_scope: bool,
    pub fail_on_risk_lenses: bool,
    pub manifest: String,
    pub contract_source: String,
    pub contract_digest: String,
    pub execute_nc: bool,
    pub nc_command: String,
    pub allow_static_nc: bool,
    pub no_gh: bool,
}

pub fn render_workflow_snippet(base_branch: &str, include_manifest: bool) -> String {
    let manifest_lines = if include_manifest {
        "          manifest: docs/reports/unit-manifest.json\n          execute-nc: \"true\"\n          nc-command: \"pytest tests/\"\n"
    } else {
        "          # Optional: bind an evidence manifest & executed negative control\n          # manifest: docs/reports/unit-manifest.json\n"
    };
    format!(
        "name: open-fleet PR Verification\n\n\
on:\n  pull_request:\n    branches: [{base_branch}]\n\n\
permissions:\n  contents: read\n\n\
jobs:\n  open-fleet-verify:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n\
      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n\
      - name: Run open-fleet PR verification gate\n        uses: ./.github/actions/open-fleet-verify\n        with:\n\
          base-ref: origin/${{{{ github.base_ref }}}}\n          run-floor-guard: \"true\"\n          run-diff-scope: \"true\"\n\
{manifest_lines}"
    )
}

pub fn run_ci_verify(args: &CiCheckArgs) -> Result<Value, String> {
    let base_ref = args.base.trim();
    if base_ref.is_empty() {
        return Err("base ref is required".to_string());
    }

    let (fg_ok, floor_result) = if args.run_floor_guard {
        let fg = eval_floor(&FloorConfig {
            base: Some(base_ref.to_string()),
            constraints: "CONSTRAINTS.md".to_string(),
            waivers: "docs/DECISIONS.md".to_string(),
            repo: args.repo.clone(),
            quiet: true,
            json: true,
        });
        let ok = fg.exit_code == 0;
        let output = if fg.findings.is_empty() {
            if ok {
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
        (
            ok,
            json!({
                "skipped": false,
                "ok": ok,
                "returncode": fg.exit_code,
                "status": if ok { "pass" } else { "fail" },
                "output": output,
            }),
        )
    } else {
        (
            true,
            json!({"skipped": true, "ok": true, "status": "skipped", "output": ""}),
        )
    };

    let (ds_ok, triggered_lenses, scope_result) = if args.run_diff_scope {
        let (code, parsed) = scope_to_json(&args.repo, Some(base_ref), args.strict_scope);
        let flags = parsed.get("flags").and_then(|v| v.as_object());
        let lenses: Vec<String> = RISK_LENS_FLAGS
            .iter()
            .filter(|&&f| {
                flags
                    .and_then(|m| m.get(f))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .map(|s| s.to_string())
            .collect();
        let err = parsed.get("error").and_then(|v| v.as_str());
        let mut ok = code == 0 && err.is_none();
        if args.fail_on_risk_lenses && !lenses.is_empty() {
            ok = false;
        }
        (
            ok,
            lenses.clone(),
            json!({
                "skipped": false,
                "ok": ok,
                "returncode": code,
                "status": if ok { "pass" } else { "fail" },
                "flags": parsed.get("flags").cloned().unwrap_or_else(|| json!({})),
                "triggered_lenses": lenses,
                "unmatched": parsed.get("unmatched").cloned().unwrap_or_else(|| json!([])),
                "error": err,
                "fail_on_risk_lenses_triggered": args.fail_on_risk_lenses && !lenses.is_empty(),
            }),
        )
    } else {
        (
            true,
            Vec::new(),
            json!({
                "skipped": true,
                "ok": true,
                "status": "skipped",
                "flags": {},
                "triggered_lenses": [],
                "unmatched": [],
                "error": Value::Null,
            }),
        )
    };

    let (ver_ok, verify_result) = if !args.manifest.trim().is_empty() {
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("open-fleet"));
        let mut v_cmd = vec![
            "verify".to_string(),
            "--manifest".to_string(),
            args.manifest.trim().to_string(),
            "--base".to_string(),
            base_ref.to_string(),
        ];
        if !args.contract_source.trim().is_empty() {
            v_cmd.extend([
                "--contract-source".to_string(),
                args.contract_source.trim().to_string(),
            ]);
        }
        if !args.contract_digest.trim().is_empty() {
            v_cmd.extend([
                "--contract-digest".to_string(),
                args.contract_digest.trim().to_string(),
            ]);
        }
        if args.execute_nc {
            v_cmd.push("--execute-nc".to_string());
        }
        if !args.nc_command.trim().is_empty() {
            v_cmd.extend([
                "--nc-command".to_string(),
                args.nc_command.trim().to_string(),
            ]);
        }
        if args.allow_static_nc {
            v_cmd.push("--allow-static-nc".to_string());
        }
        if args.no_gh {
            v_cmd.push("--no-gh".to_string());
        }
        match Command::new(exe)
            .args(&v_cmd)
            .current_dir(&args.repo)
            .env("OPEN_FLEET_ROOT", &args.root)
            .stdin(Stdio::null())
            .output()
        {
            Ok(o) => {
                let code = o.status.code().unwrap_or(1);
                let ok = code == 0;
                let out = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
                .trim()
                .to_string();
                (
                    ok,
                    json!({
                        "skipped": false,
                        "ok": ok,
                        "returncode": code,
                        "status": if ok { "pass" } else { "fail" },
                        "output": out,
                    }),
                )
            }
            Err(err) => (
                false,
                json!({
                    "skipped": false,
                    "ok": false,
                    "returncode": 127,
                    "status": "fail",
                    "output": err.to_string(),
                }),
            ),
        }
    } else {
        (
            true,
            json!({"skipped": true, "ok": true, "status": "skipped", "output": ""}),
        )
    };

    let overall_ok = fg_ok && ds_ok && ver_ok;
    let res = json!({
        "ok": overall_ok,
        "base": base_ref,
        "repo": args.repo.display().to_string(),
        "floor_guard": floor_result,
        "diff_scope": scope_result,
        "verify": verify_result,
        "triggered_lenses": triggered_lenses,
    });
    write_github_outputs(&res);
    Ok(res)
}

pub fn render_step_summary(result: &Value) -> String {
    let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let overall = if ok { "PASS" } else { "FAIL" };
    let base = result.get("base").and_then(|v| v.as_str()).unwrap_or("");
    let lenses: Vec<&str> = result
        .get("triggered_lenses")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    let lenses_s = if lenses.is_empty() {
        "none".to_string()
    } else {
        lenses.join(", ")
    };
    let fg = result.get("floor_guard");
    let ds = result.get("diff_scope");
    let vr = result.get("verify");

    let status_up = |v: Option<&Value>| {
        v.and_then(|o| o.get("status"))
            .and_then(|s| s.as_str())
            .unwrap_or("skipped")
            .to_ascii_uppercase()
    };
    let first_line = |v: Option<&Value>, fallback: &str| {
        v.and_then(|o| o.get("output"))
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .and_then(|s| s.lines().next())
            .unwrap_or(fallback)
            .chars()
            .take(120)
            .collect::<String>()
    };
    let ds_err = ds
        .and_then(|o| o.get("error"))
        .and_then(|s| s.as_str())
        .map(|e| format!(" · error={e}"))
        .unwrap_or_default();

    let mut lines = vec![
        format!("## open-fleet PR Verification — `{overall}`"),
        String::new(),
        format!("- **Base ref:** `{base}`"),
        format!("- **Triggered risk lenses:** `{lenses_s}`"),
        String::new(),
        "| Gate | Status | Detail |".to_string(),
        "|---|---|---|".to_string(),
        format!(
            "| `floor_guard` | `{}` | {} |",
            status_up(fg),
            first_line(fg, "skipped")
        ),
        format!(
            "| `diff_scope` | `{}` | lenses={lenses_s}{ds_err} |",
            status_up(ds)
        ),
        format!(
            "| `verify` | `{}` | {} |",
            status_up(vr),
            first_line(vr, "skipped (no manifest provided)")
        ),
        String::new(),
    ];
    if !fg
        .and_then(|o| o.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        if let Some(out) = fg.and_then(|o| o.get("output")).and_then(|s| s.as_str()) {
            if !out.is_empty() {
                let cap: String = out.chars().take(3000).collect();
                lines.extend([
                    "### Floor Guard Findings".to_string(),
                    "```text".to_string(),
                    cap,
                    "```".to_string(),
                    String::new(),
                ]);
            }
        }
    }
    lines.join("\n")
}

fn write_github_outputs(res: &Value) {
    if let Ok(out_path) = env::var("GITHUB_OUTPUT") {
        let p = out_path.trim();
        if !p.is_empty() {
            if let Ok(mut fh) = OpenOptions::new().create(true).append(true).open(p) {
                let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                let fg_s = res
                    .get("floor_guard")
                    .and_then(|o| o.get("status"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("skipped");
                let ds_s = res
                    .get("diff_scope")
                    .and_then(|o| o.get("status"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("skipped");
                let vr_s = res
                    .get("verify")
                    .and_then(|o| o.get("status"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("skipped");
                let lenses: Vec<&str> = res
                    .get("triggered_lenses")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
                    .collect();
                let _ = writeln!(fh, "overall-ok={}", if ok { "true" } else { "false" });
                let _ = writeln!(fh, "floor-guard-status={fg_s}");
                let _ = writeln!(fh, "diff-scope-status={ds_s}");
                let _ = writeln!(fh, "verify-status={vr_s}");
                let _ = writeln!(fh, "triggered-lenses={}", lenses.join(","));
            }
        }
    }
    if let Ok(sum_path) = env::var("GITHUB_STEP_SUMMARY") {
        let p = sum_path.trim();
        if !p.is_empty() {
            if let Ok(mut fh) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(fh, "{}", render_step_summary(res));
            }
        }
    }
}
