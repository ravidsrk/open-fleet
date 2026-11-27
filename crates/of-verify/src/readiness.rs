//! Native Rust port of `open_fleet/readiness.py`:
//! honest proof-graduation & multi-harness certification readiness workbench.

use of_catalog::{certification_summary, list_missions, load_retained_runs};
use of_install::{doctor, which};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const GRADUATION_PRIORITY: &[&str] = &[
    "root-cause",
    "deflake-it",
    "floor-it",
    "document-it",
    "modernize-it",
    "map-it",
    "reshape-it",
    "speed-it",
    "migrate-it",
    "oncall-it",
    "access-it",
    "attest-it",
    "absorb-it",
    "oss-contribute",
    "field-test-it",
    "offload-it",
    "pin-it",
];

fn run_py_helper(root: &Path, script_rel: &str, extra: &[&str]) -> Value {
    let python = which("python3")
        .or_else(|| which("python"))
        .unwrap_or_else(|| PathBuf::from("python3"));
    let script = root.join(script_rel);
    match Command::new(python)
        .arg("-I")
        .arg(&script)
        .args(extra)
        .current_dir(root)
        .env("OPEN_FLEET_ROOT", root)
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) => {
            let code = o.status.code().unwrap_or(1);
            json!({
                "ok": code == 0,
                "returncode": code,
                "stdout": String::from_utf8_lossy(&o.stdout).into_owned(),
                "stderr": String::from_utf8_lossy(&o.stderr).into_owned(),
            })
        }
        Err(err) => json!({
            "ok": false,
            "returncode": 127,
            "stdout": "",
            "stderr": err.to_string(),
        }),
    }
}

pub fn run_certification_check(root: &Path) -> Value {
    let root_s = root.display().to_string();
    let res = run_py_helper(
        root,
        "runtime/scripts/certification.py",
        &["check", "--root", &root_s],
    );
    let combined = format!(
        "{}\n{}",
        res.get("stdout").and_then(|v| v.as_str()).unwrap_or(""),
        res.get("stderr").and_then(|v| v.as_str()).unwrap_or("")
    );
    let lines: Vec<&str> = combined.lines().filter(|l| !l.trim().is_empty()).collect();
    let failures: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.starts_with("FAIL:"))
        .collect();
    let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    json!({
        "ok": ok,
        "returncode": res.get("returncode").cloned().unwrap_or(json!(1)),
        "stdout": res.get("stdout").cloned().unwrap_or(json!("")),
        "stderr": res.get("stderr").cloned().unwrap_or(json!("")),
        "fresh": ok && failures.is_empty(),
        "failure_count": failures.len(),
        "failures": failures,
        "summary": lines.last().copied().unwrap_or(""),
    })
}

pub fn run_negative_probes(root: &Path) -> Value {
    let res = run_py_helper(root, "runtime/scripts/first_run.py", &["probes", "--json"]);
    let receipt: Value = res
        .get("stdout")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    json!({
        "ok": res.get("ok").cloned().unwrap_or(json!(false)),
        "returncode": res.get("returncode").cloned().unwrap_or(json!(1)),
        "stdout": res.get("stdout").cloned().unwrap_or(json!("")),
        "stderr": res.get("stderr").cloned().unwrap_or(json!("")),
        "receipt": receipt,
    })
}

pub fn readiness_report(root: &Path, engine_version: &str, run_cert_check: bool) -> Value {
    let missions = list_missions(root, None, None, false);
    let cert = certification_summary(root);
    let runs = load_retained_runs(root);
    let doc = doctor(root, engine_version);

    let prio_rank: HashMap<&str, usize> = GRADUATION_PRIORITY
        .iter()
        .enumerate()
        .map(|(idx, &name)| (name, idx))
        .collect();

    let mut proven: Vec<Value> = Vec::new();
    let mut candidates: Vec<(usize, String, Value)> = Vec::new();

    for m in &missions {
        if m.proof == "external-run" || m.proof == "self-run" {
            proven.push(json!({
                "mission": m.name,
                "proof": m.proof,
                "proof_evidence": m.proof_evidence,
                "category": m.category,
            }));
        } else {
            let needs_orca = m
                .capabilities
                .required
                .iter()
                .any(|c| c == "cap:orca-self-audit");
            let runtime_hint = if needs_orca { "orca" } else { "posix" };
            let mode_hint = if matches!(m.name.as_str(), "map-it" | "root-cause" | "pin-it") {
                "readonly"
            } else {
                "write"
            };
            let rank = prio_rank.get(m.name.as_str()).copied().unwrap_or(99);
            let preflight_cmd = format!(
                "open-fleet preflight --mission {} --runtime {runtime_hint} --mode {mode_hint}{}",
                m.name,
                if mode_hint == "write" {
                    " --base <integration-branch>"
                } else {
                    ""
                }
            );
            candidates.push((
                rank,
                m.name.clone(),
                json!({
                    "mission": m.name,
                    "priority_rank": rank,
                    "category": m.category,
                    "current_proof": m.proof,
                    "target_proof": "self-run",
                    "recommended_runtime": runtime_hint,
                    "required_capabilities": m.capabilities.required,
                    "preflight_cmd": preflight_cmd,
                    "graduation_requirements": [
                        "Retained run report under docs/runs/ with RUN: header (verifier=GREEN)",
                        "Unit evidence manifest in the run directory verified by verify.py",
                        "SHA-256 inventory re-hashed cleanly by runtime/scripts/run_report.py",
                        "Run index row added under docs/runs/index/<run>.json",
                    ],
                }),
            ));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let grad_backlog: Vec<Value> = candidates.into_iter().map(|(_, _, v)| v).collect();

    let mut harness_opportunities: Vec<Value> = Vec::new();
    let mut actionable: Vec<String> = Vec::new();
    if let Some(harnesses) = cert.get("harnesses").and_then(|v| v.as_array()) {
        let mut sorted: Vec<&Value> = harnesses.iter().collect();
        sorted.sort_by_key(|h| h.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        for h in sorted {
            let hname = h.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let live_count = h
                .get("cell_counts")
                .and_then(|c| c.get("live-witnessed"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let fix_count = h
                .get("cell_counts")
                .and_then(|c| c.get("fixture-tested"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let installed_path = doc.detected_harnesses.get(hname);
            let installed = installed_path.is_some();
            let needs_live = live_count < 2;
            if installed && needs_live {
                actionable.push(hname.to_string());
            }
            harness_opportunities.push(json!({
                "harness": hname,
                "installed_locally": installed,
                "binary_path": installed_path.cloned().unwrap_or_default(),
                "certified_version": h.get("version").cloned().unwrap_or(Value::Null),
                "live_witnessed_profiles": live_count,
                "fixture_tested_profiles": fix_count,
                "needs_live_witness": needs_live,
                "inert_probe_cmd": format!("python3 runtime/scripts/first_run.py --profile ro --agent {hname} --json"),
                "live_container_cmd": format!("python3 scripts/live_container.py run --arm first-run --agent {hname}"),
            }));
        }
    }

    let binding_runs_count = runs.iter().filter(|r| r.binds_yes).count();
    let cert_check = if run_cert_check {
        run_certification_check(root)
    } else {
        Value::Null
    };
    json!({
        "proven_count": proven.len(),
        "doctrine_only_count": grad_backlog.len(),
        "total_missions": missions.len(),
        "binding_runs_count": binding_runs_count,
        "proven_missions": proven,
        "graduation_backlog": grad_backlog,
        "harness_certification_backlog": harness_opportunities,
        "locally_actionable_harnesses": actionable,
        "certification_check": cert_check,
    })
}
