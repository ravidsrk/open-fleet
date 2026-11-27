//! Native Rust port of `open_fleet/sessions.py`:
//! progressive <5K-token/phase mission state machines with enforced receipts,
//! human one-way gates, and fail-closed `chain_check` terminal validation.

use crate::chain_check::{canonical, classify};
use chrono::Utc;
use of_catalog::{get_mission, list_missions, Mission};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SCHEMA_VERSION: &str = "open-fleet-session/v1";
pub const PHASE_TOKEN_CEILING: usize = 5000;

const READONLY_MISSIONS: &[&str] = &["review-it", "map-it", "root-cause", "pin-it"];
const FREEZE_GATE_MISSIONS: &[&str] = &[
    "ship-it",
    "clean-sweep",
    "map-it",
    "harden-it",
    "prove-it",
    "deflake-it",
    "speed-it",
    "modernize-it",
    "reshape-it",
    "migrate-it",
    "oncall-it",
    "document-it",
    "floor-it",
    "access-it",
    "attest-it",
    "offload-it",
    "field-test-it",
    "oss-contribute",
    "absorb-it",
];
const DISALLOWED_HUMAN_ACTORS: &[&str] = &[
    "",
    "agent",
    "ai",
    "auto",
    "bot",
    "claude",
    "codex",
    "coordinator",
    "gemini",
    "llm",
    "model",
    "opencode",
    "orca",
    "system",
    "worker",
];

fn session_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$").expect("regex"))
}

fn terminal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^- \*\*([A-Z][A-Z0-9-]*)\*\*").expect("regex"))
}

fn inline_terminal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([A-Z][A-Z0-9_]+(?:-[A-Z0-9_]+)*)`").expect("regex"))
}

fn terminal_section_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?ms)^##\s+Terminal\b[^\n]*\n(.*?)(?:\n##\s+|\z)").expect("regex")
    })
}

fn phase_playbooks(phase_id: &str) -> &'static [&'static str] {
    match phase_id {
        "preflight" => &["sandbox-policy", "gate-classification"],
        "freeze" => &[
            "decide-and-freeze",
            "triage-state",
            "linear-enumeration",
            "plan-review",
        ],
        "execute" => &[
            "decompose-dag",
            "build-change",
            "remediate-finding",
            "dispatch-lifecycle",
            "attention-budget",
        ],
        "verify" => &[
            "acceptance-review",
            "risk-review",
            "runtime-prove",
            "evidence-manifest",
            "reviewed-sha-freshness",
        ],
        "promote" => &[
            "merge-serialization",
            "release",
            "publish-evidence",
            "human-handoff",
            "mission-chaining",
        ],
        _ => &[],
    }
}

fn phase_mcp_tools(phase_id: &str) -> &'static [&'static str] {
    match phase_id {
        "preflight" => &["fleet_doctor", "fleet_preflight", "fleet_session_advance"],
        "freeze" => &[
            "fleet_decisions",
            "fleet_session_approve_gate",
            "fleet_session_advance",
        ],
        "execute" => &[
            "fleet_status",
            "fleet_diff_scope",
            "fleet_floor_check",
            "fleet_session_advance",
        ],
        "verify" => &[
            "fleet_diff_scope",
            "fleet_floor_check",
            "fleet_solo_review",
            "fleet_verify_manifest",
            "fleet_session_advance",
        ],
        "promote" => &[
            "fleet_session_approve_gate",
            "fleet_verify_manifest",
            "fleet_session_advance",
        ],
        _ => &["fleet_status"],
    }
}

fn utc_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn estimate_tokens(val: &Value) -> usize {
    let raw = serde_json::to_string(val).unwrap_or_default();
    raw.len().div_ceil(4).max(1)
}

pub fn default_sessions_dir(repo: &Path) -> PathBuf {
    let base = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    if base.join(".git").exists() {
        return base.join(".orca/sessions");
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".open-fleet/sessions")
}

fn atomic_write_json(path: &Path, data: &Value) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".session-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| format!("tempfile failed: {e}"))?;
    let text = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    tmp.write_all(text.as_bytes())
        .and_then(|_| tmp.write_all(b"\n"))
        .map_err(|e| format!("write failed: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persist {} failed: {}", path.display(), e.error))?;
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<String, String> {
    let sid = session_id.trim();
    if !session_id_re().is_match(sid) {
        return Err(format!("invalid session_id: {session_id:?}"));
    }
    Ok(sid.to_string())
}

fn declared_terminals(mission: &Mission) -> Vec<String> {
    let body = mission.body.as_deref().unwrap_or("");
    let mut found: Vec<String> = terminal_re()
        .captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();
    if found.is_empty() {
        if let Some(sec) = terminal_section_re()
            .captures(body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
        {
            for caps in inline_terminal_re().captures_iter(sec) {
                let tok = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if tok.len() >= 2
                    && !matches!(tok, "BASE" | "HEAD" | "SHA" | "PR" | "OPS")
                    && !found.iter().any(|x| x == tok)
                {
                    found.push(tok.to_string());
                }
            }
        }
    }
    found
}

pub fn build_phase_plan(mission: &Mission) -> Vec<Value> {
    let name = mission.name.as_str();
    let is_readonly = READONLY_MISSIONS.contains(&name);
    let has_freeze_gate = FREEZE_GATE_MISSIONS.contains(&name);
    let mut all_refs: BTreeSet<&str> = mission.composes.iter().map(|s| s.as_str()).collect();
    for d in &mission.deferred_reads {
        all_refs.insert(d.as_str());
    }

    let pick_refs = |phase_id: &str| -> Vec<&'static str> {
        let cands = phase_playbooks(phase_id);
        let mut picked: Vec<&'static str> = cands
            .iter()
            .copied()
            .filter(|r| all_refs.contains(r))
            .collect();
        if picked.is_empty() && !cands.is_empty() {
            picked.push(cands[0]);
        }
        picked
    };

    vec![
        json!({
            "id": "preflight",
            "title": "Preflight & Capability Gate",
            "mode": if is_readonly { "readonly" } else { "write" },
            "requires_human_gate": false,
            "gate_name": Value::Null,
            "requires_receipt": "preflight",
            "playbooks": pick_refs("preflight"),
            "directive": format!(
                "Run fail-closed preflight for `{name}` before dispatching any worker. {}",
                if is_readonly {
                    "Read-only mission: verify quarantine and capability support."
                } else {
                    "Write mission: confirm integration BASE != default branch, clean baseline, and capabilities."
                }
            ),
        }),
        json!({
            "id": "freeze",
            "title": "Freeze Scope / Pin Fixed Point",
            "mode": if has_freeze_gate { "gate" } else { "readonly" },
            "requires_human_gate": has_freeze_gate,
            "gate_name": if has_freeze_gate { json!("freeze") } else { Value::Null },
            "requires_receipt": "freeze_contract",
            "playbooks": pick_refs("freeze"),
            "directive": if has_freeze_gate {
                "Freeze the T0 acceptance criteria / finding denominator with a SHA-256 digest and obtain explicit human approval before dispatching build workers."
            } else {
                "Pin the exact fixed-point commit / PR SHA and confirm a non-empty diff or symptom repro."
            },
        }),
        json!({
            "id": "execute",
            "title": "Isolated Worker Execution",
            "mode": if is_readonly { "readonly" } else { "write" },
            "requires_human_gate": false,
            "gate_name": Value::Null,
            "requires_receipt": "execution",
            "playbooks": pick_refs("execute"),
            "directive": "Dispatch isolated workers (at most ONE upstream methodology router per worker) under attention-budget WIP limits. Never co-mount two routers in one worker.",
        }),
        json!({
            "id": "verify",
            "title": "Independent Verification & Floor Guard",
            "mode": "verify",
            "requires_human_gate": false,
            "gate_name": Value::Null,
            "requires_receipt": "verify",
            "playbooks": pick_refs("verify"),
            "directive": "Run diff_scope + floor_guard + independent SHA-bound verification (`verify.py`) outside the worker session. For mutation units, execute the negative control or record RED.",
        }),
        json!({
            "id": "promote",
            "title": "Close / Promotion Gate",
            "mode": "gate",
            "requires_human_gate": !is_readonly,
            "gate_name": if is_readonly { Value::Null } else { json!("promote") },
            "requires_receipt": "terminal",
            "playbooks": pick_refs("promote"),
            "directive": if is_readonly {
                "Record the verified terminal outcome (`GO` / `NO-GO` / `MAPPED` / `PINNED`) bound to the reviewed SHA."
            } else {
                "Stop at PROMOTION_READY / BUILT with traceability evidence, or obtain an explicit one-way human grant before releasing/deploying."
            },
        }),
    ]
}

fn load_compact_doc_excerpt(root: &Path, bare_name: &str, max_chars: usize) -> Option<Value> {
    for folder in ["playbooks", "runtime"] {
        let cand = root.join(folder).join(format!("{bare_name}.md"));
        if cand.is_file() {
            let raw = fs::read_to_string(&cand).ok()?;
            let lines: Vec<&str> = raw.lines().collect();
            let title = lines
                .first()
                .map(|l| l.trim_start_matches(['#', ' ']).trim())
                .unwrap_or(bare_name);
            let mut parts: Vec<String> = Vec::new();
            let mut total = 0usize;
            for ln in lines {
                let s = ln.trim_end();
                if s.is_empty() && parts.last().map(|p| p.is_empty()).unwrap_or(false) {
                    continue;
                }
                if total + s.len() + 1 > max_chars {
                    parts.push("… [truncated; read full file only if needed]".to_string());
                    break;
                }
                parts.push(s.to_string());
                total += s.len() + 1;
            }
            return Some(json!({
                "name": bare_name,
                "path": format!("{folder}/{bare_name}.md"),
                "title": title,
                "excerpt": parts.join("\n").trim(),
            }));
        }
    }
    None
}

fn blocking_requirements(state: &Map<String, Value>) -> Vec<String> {
    if state.get("status").and_then(|v| v.as_str()) != Some("active") {
        return Vec::new();
    }
    let Some(phases) = state.get("phases").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let idx = state
        .get("current_phase_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let Some(phase) = phases.get(idx).and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut blockers = Vec::new();
    let req_receipt = phase
        .get("requires_receipt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let receipts = state.get("receipts").and_then(|v| v.as_object());
    if !req_receipt.is_empty() && req_receipt != "terminal" {
        let ok = receipts
            .and_then(|m| m.get(req_receipt))
            .and_then(|v| v.as_object())
            .and_then(|r| r.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !ok {
            blockers.push(format!(
                "missing passing '{req_receipt}' receipt (supply receipt with ok=true)"
            ));
        }
    }
    if phase
        .get("requires_human_gate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let gname = phase
            .get("gate_name")
            .and_then(|v| v.as_str())
            .or_else(|| phase.get("id").and_then(|v| v.as_str()))
            .unwrap_or("");
        let approved = state
            .get("approvals")
            .and_then(|v| v.as_object())
            .and_then(|a| a.get(gname))
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("approved"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !approved {
            blockers.push(format!(
                "human one-way gate '{gname}' not approved (call approve_gate with human actor + rationale)"
            ));
        }
    }
    blockers
}

pub fn build_phase_packet(state: &Map<String, Value>, root: &Path) -> Value {
    let empty_phases: Vec<Value> = Vec::new();
    let phases = state
        .get("phases")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_phases);
    let idx = (state
        .get("current_phase_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize)
        .min(phases.len().saturating_sub(1));
    let phase = phases.get(idx).and_then(|v| v.as_object());
    let phase_id = phase
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mission_name = state.get("mission").and_then(|v| v.as_str()).unwrap_or("");
    let mission_info = get_mission(root, mission_name);

    let playbooks_in: Vec<&str> = phase
        .and_then(|p| p.get("playbooks"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    let per_doc_cap = (2600 / playbooks_in.len().max(1)).clamp(550, 1100);
    let mut docs = Vec::new();
    for ref_name in playbooks_in.iter().take(4) {
        if let Some(loaded) = load_compact_doc_excerpt(root, ref_name, per_doc_cap) {
            docs.push(loaded);
        }
    }

    let next_phase = phases
        .get(idx + 1)
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("COMPLETE");
    let blockers = blocking_requirements(state);
    let ready =
        blockers.is_empty() && state.get("status").and_then(|v| v.as_str()) == Some("active");
    let mut receipts_recorded: Vec<String> = state
        .get("receipts")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    receipts_recorded.sort();

    let identity_val = mission_info
        .as_ref()
        .and_then(|m| serde_json::to_value(&m.identity).ok())
        .unwrap_or_else(|| json!({}));

    let mut packet = json!({
        "session_id": state.get("session_id").cloned().unwrap_or(Value::Null),
        "mission": mission_name,
        "proof": state.get("proof").cloned().unwrap_or(Value::Null),
        "status": state.get("status").cloned().unwrap_or(Value::Null),
        "goal": state.get("goal").cloned().unwrap_or(Value::Null),
        "base": state.get("base").cloned().unwrap_or(Value::Null),
        "runtime": state.get("runtime").cloned().unwrap_or(Value::Null),
        "phase": {
            "id": phase_id,
            "index": idx,
            "total": phases.len(),
            "title": phase.and_then(|p| p.get("title")).cloned().unwrap_or(Value::Null),
            "mode": phase.and_then(|p| p.get("mode")).cloned().unwrap_or(Value::Null),
            "requires_human_gate": phase.and_then(|p| p.get("requires_human_gate")).and_then(|v| v.as_bool()).unwrap_or(false),
            "gate_name": phase.and_then(|p| p.get("gate_name")).cloned().unwrap_or(Value::Null),
            "directive": phase.and_then(|p| p.get("directive")).cloned().unwrap_or(Value::Null),
            "next_phase": next_phase,
        },
        "identity_contract": identity_val,
        "blocking_requirements": blockers,
        "ready_to_advance": ready,
        "mcp_tools_for_phase": phase_mcp_tools(phase_id),
        "phase_playbooks": docs,
        "approvals": state.get("approvals").cloned().unwrap_or_else(|| json!({})),
        "receipts_recorded": receipts_recorded,
        "terminal_state": state.get("terminal_state").cloned().unwrap_or(Value::Null),
        "terminal_class": state.get("terminal_class").cloned().unwrap_or(Value::Null),
    });

    let phase_tokens = estimate_tokens(&packet);
    let full_budget = state
        .get("full_activation_budget_tokens")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .filter(|&n| n > 0)
        .or_else(|| {
            mission_info
                .as_ref()
                .map(|m| m.activation_budget_tokens.max(0) as usize)
        })
        .unwrap_or(0);
    let saved = full_budget.saturating_sub(phase_tokens);
    let reduction_pct = if full_budget > 0 {
        (((saved as f64) / (full_budget as f64)) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    if let Some(obj) = packet.as_object_mut() {
        obj.insert(
            "token_budget".to_string(),
            json!({
                "phase_tokens_est": phase_tokens,
                "phase_ceiling_tokens": PHASE_TOKEN_CEILING,
                "within_ceiling": phase_tokens < PHASE_TOKEN_CEILING,
                "full_activation_budget_tokens": full_budget,
                "saved_tokens": saved,
                "reduction_pct": reduction_pct,
            }),
        );
    }
    packet
}

pub struct StartSessionArgs<'a> {
    pub mission: &'a str,
    pub goal: &'a str,
    pub root: &'a Path,
    pub repo: &'a Path,
    pub sessions_dir: Option<&'a Path>,
    pub base_branch: &'a str,
    pub runtime: &'a str,
}

pub fn start_session(args: &StartSessionArgs<'_>) -> Result<Value, String> {
    let Some(mission_info) = get_mission(args.root, args.mission) else {
        return Err(format!("unknown mission: {:?}", args.mission));
    };
    let goal_clean = args.goal.trim();
    if goal_clean.is_empty() {
        return Err("goal must be a non-empty string".to_string());
    }
    let phases = build_phase_plan(&mission_info);
    let declared = declared_terminals(&mission_info);
    let mut rnd = [0u8; 3];
    let _ = getrandom::getrandom(&mut rnd);
    let ts_id = Utc::now().format("%Y%m%d%H%M%S");
    let session_id = format!("{}-{ts_id}-{}", mission_info.name, hex::encode(rnd));
    let sdir = args
        .sessions_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sessions_dir(args.repo));
    let now = utc_now();
    let rt = if args.runtime.trim().is_empty() {
        "auto"
    } else {
        args.runtime.trim()
    };
    let state_val = json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "mission": mission_info.name,
        "proof": mission_info.proof,
        "category": mission_info.category,
        "goal": goal_clean,
        "repo": fs::canonicalize(args.repo).unwrap_or_else(|_| args.repo.to_path_buf()).display().to_string(),
        "base": args.base_branch.trim(),
        "runtime": rt,
        "status": "active",
        "current_phase_index": 0,
        "current_phase": "preflight",
        "terminal_state": Value::Null,
        "terminal_class": Value::Null,
        "declared_terminals": declared,
        "allowed_terminals": declared,
        "phases": phases,
        "approvals": {},
        "receipts": {},
        "history": [{
            "ts": now,
            "event": "session_started",
            "phase": "preflight",
            "detail": format!("Initialized progressive session for {}", mission_info.name),
        }],
        "created_at": now,
        "updated_at": now,
        "full_activation_budget_tokens": mission_info.activation_budget_tokens,
    });
    atomic_write_json(&sdir.join(format!("{session_id}.json")), &state_val)?;
    let packet = state_val
        .as_object()
        .map(|m| build_phase_packet(m, args.root))
        .unwrap_or_else(|| json!({}));
    Ok(json!({
        "session": state_val,
        "packet": packet,
    }))
}

pub fn load_session(
    session_id: &str,
    repo: &Path,
    sessions_dir: Option<&Path>,
) -> Result<Map<String, Value>, String> {
    let sid = validate_session_id(session_id)?;
    let sdir = sessions_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sessions_dir(repo));
    let path = sdir.join(format!("{sid}.json"));
    if !path.is_file() {
        return Err(format!("session not found: {sid}"));
    }
    let text =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let val: Value =
        serde_json::from_str(&text).map_err(|e| format!("corrupt session file: {e}"))?;
    let Some(map) = val.as_object() else {
        return Err(format!(
            "corrupt or incompatible session file: {}",
            path.display()
        ));
    };
    if map.get("schema_version").and_then(|v| v.as_str()) != Some(SCHEMA_VERSION) {
        return Err(format!(
            "corrupt or incompatible session file: {}",
            path.display()
        ));
    }
    Ok(map.clone())
}

pub fn list_sessions(repo: &Path, sessions_dir: Option<&Path>) -> Vec<Value> {
    let sdir = sessions_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sessions_dir(repo));
    let Ok(rd) = fs::read_dir(&sdir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths.reverse();
    let mut out = Vec::new();
    for path in paths {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(Value::Object(data)) = serde_json::from_str(&text) else {
            continue;
        };
        if data.get("schema_version").and_then(|v| v.as_str()) != Some(SCHEMA_VERSION) {
            continue;
        }
        let mut approvals: Vec<String> = data
            .get("approvals")
            .and_then(|v| v.as_object())
            .map(|a| a.keys().cloned().collect())
            .unwrap_or_default();
        approvals.sort();
        let total_phases = data
            .get("phases")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        out.push(json!({
            "session_id": data.get("session_id").cloned().unwrap_or(Value::Null),
            "mission": data.get("mission").cloned().unwrap_or(Value::Null),
            "goal": data.get("goal").cloned().unwrap_or(Value::Null),
            "status": data.get("status").cloned().unwrap_or(Value::Null),
            "current_phase": data.get("current_phase").cloned().unwrap_or(Value::Null),
            "current_phase_index": data.get("current_phase_index").cloned().unwrap_or(Value::Null),
            "total_phases": total_phases,
            "terminal_state": data.get("terminal_state").cloned().unwrap_or(Value::Null),
            "terminal_class": data.get("terminal_class").cloned().unwrap_or(Value::Null),
            "base": data.get("base").cloned().unwrap_or(Value::Null),
            "updated_at": data.get("updated_at").cloned().unwrap_or(Value::Null),
            "approvals": approvals,
        }));
    }
    out
}

pub struct ApproveGateArgs<'a> {
    pub session_id: &'a str,
    pub gate: &'a str,
    pub actor: &'a str,
    pub rationale: &'a str,
    pub contract_digest: &'a str,
    pub root: &'a Path,
    pub repo: &'a Path,
    pub sessions_dir: Option<&'a Path>,
}

pub fn approve_gate(args: &ApproveGateArgs<'_>) -> Result<Value, String> {
    let sdir = args
        .sessions_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sessions_dir(args.repo));
    let mut state = load_session(args.session_id, args.repo, Some(&sdir))?;
    if state.get("status").and_then(|v| v.as_str()) != Some("active") {
        return Err(format!(
            "session {} is not active (status={:?})",
            args.session_id,
            state.get("status")
        ));
    }
    let gate_clean = args.gate.trim().to_ascii_lowercase();
    let actor_clean = args.actor.trim();
    let rationale_clean = args.rationale.trim();
    if gate_clean.is_empty() {
        return Err("gate name is required".to_string());
    }
    if DISALLOWED_HUMAN_ACTORS.contains(&actor_clean.to_ascii_lowercase().as_str())
        || actor_clean.len() < 2
    {
        return Err(format!(
            "one-way gate {gate_clean:?} requires a real human actor identity (refused non-human/blank actor {:?}; agents never self-approve one-way gates)",
            args.actor
        ));
    }
    if rationale_clean.len() < 4 {
        return Err(
            "rationale must be at least 4 characters explaining the human decision".to_string(),
        );
    }
    let valid_gates: BTreeSet<String> = state
        .get("phases")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            p.get("gate_name")
                .and_then(|g| g.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    if !valid_gates.contains(&gate_clean) {
        return Err(format!(
            "gate {gate_clean:?} is not a one-way gate for mission {:?}; valid={valid_gates:?}",
            state.get("mission")
        ));
    }

    let now = utc_now();
    let digest_val = if gate_clean == "freeze" && args.contract_digest.trim().is_empty() {
        let m = state.get("mission").and_then(|v| v.as_str()).unwrap_or("");
        let g = state.get("goal").and_then(|v| v.as_str()).unwrap_or("");
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                format!("{m}:{g}:{rationale_clean}").as_bytes()
            ))
        )
    } else {
        args.contract_digest.trim().to_string()
    };

    let approval_record = json!({
        "gate": gate_clean,
        "approved": true,
        "actor": actor_clean,
        "rationale": rationale_clean,
        "contract_digest": digest_val,
        "ts": now,
    });
    state
        .entry("approvals".to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .map(|m| m.insert(gate_clean.clone(), approval_record.clone()));
    if gate_clean == "freeze" {
        state
            .entry("receipts".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|m| {
                m.insert(
                    "freeze_contract".to_string(),
                    json!({
                        "ok": true,
                        "contract_digest": digest_val,
                        "approved_by": actor_clean,
                        "ts": now,
                    }),
                )
            });
    }
    let cur_phase = state.get("current_phase").cloned().unwrap_or(Value::Null);
    if let Some(arr) = state
        .entry("history".to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
    {
        arr.push(json!({
            "ts": now,
            "event": "gate_approved",
            "phase": cur_phase,
            "gate": gate_clean,
            "actor": actor_clean,
            "detail": rationale_clean,
        }));
    }
    state.insert("updated_at".to_string(), json!(now));
    let sid = state
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or(args.session_id)
        .to_string();
    let state_val = Value::Object(state.clone());
    atomic_write_json(&sdir.join(format!("{sid}.json")), &state_val)?;
    let packet = build_phase_packet(&state, args.root);
    Ok(json!({
        "session": state_val,
        "approval": approval_record,
        "packet": packet,
    }))
}

pub struct AdvanceSessionArgs<'a> {
    pub session_id: &'a str,
    pub receipt: Option<Map<String, Value>>,
    pub terminal_state: &'a str,
    pub root: &'a Path,
    pub repo: &'a Path,
    pub sessions_dir: Option<&'a Path>,
}

pub fn advance_session(args: &AdvanceSessionArgs<'_>) -> Result<Value, String> {
    let sdir = args
        .sessions_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sessions_dir(args.repo));
    let mut state = load_session(args.session_id, args.repo, Some(&sdir))?;
    if state.get("status").and_then(|v| v.as_str()) != Some("active") {
        return Err(format!(
            "session {} is already {:?} (terminal={:?})",
            args.session_id,
            state.get("status"),
            state.get("terminal_state")
        ));
    }
    let phases = state
        .get("phases")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let idx = state
        .get("current_phase_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let Some(phase) = phases.get(idx).and_then(|v| v.as_object()) else {
        return Err("invalid phase index".to_string());
    };
    let phase_id = phase
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let req_receipt = phase
        .get("requires_receipt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let now = utc_now();

    if let Some(mut rec) = args.receipt.clone() {
        let key = rec
            .get("kind")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| req_receipt.clone())
            .unwrap_or_else(|| phase_id.clone());
        rec.insert("ts".to_string(), json!(now));
        state
            .entry("receipts".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|m| m.insert(key, Value::Object(rec)));
    }

    let sid = state
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or(args.session_id)
        .to_string();
    let is_final = idx + 1 == phases.len();
    if is_final {
        let term = if !args.terminal_state.trim().is_empty() {
            args.terminal_state.trim().to_string()
        } else {
            args.receipt
                .as_ref()
                .and_then(|r| r.get("terminal_state"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string()
        };
        if term.is_empty() {
            return Err(
                "final phase requires terminal_state (e.g. PROMOTION_READY, BUILT, GO, NO-GO, DRY)"
                    .to_string(),
            );
        }
        let canon = canonical(&term);
        let t_class = classify(&canon);
        if t_class == "unknown" {
            return Err(format!(
                "unrecognized terminal state {term:?} (rejected fail-closed by chain_check)"
            ));
        }
        let req_gate = phase
            .get("requires_human_gate")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if req_gate && matches!(canon.as_str(), "RELEASED" | "DEPLOYED-AND-VERIFIED") {
            let approved = state
                .get("approvals")
                .and_then(|v| v.as_object())
                .and_then(|a| a.get("promote"))
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("approved"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !approved {
                return Err(format!(
                    "terminal state {canon} is a one-way release/deploy action and requires human gate 'promote' approval"
                ));
            }
        }
        let verify_ok = state
            .get("receipts")
            .and_then(|v| v.as_object())
            .and_then(|r| r.get("verify"))
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if t_class == "clean" && !verify_ok {
            return Err(format!(
                "cannot close with clean terminal {canon} without a passing 'verify' receipt"
            ));
        }
        let status = match t_class {
            "clean" => "completed",
            "handoff" => "handoff",
            _ => "degraded",
        };
        state.insert("terminal_state".to_string(), json!(canon));
        state.insert("terminal_class".to_string(), json!(t_class));
        state.insert("status".to_string(), json!(status));
        if let Some(arr) = state
            .entry("history".to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            arr.push(json!({
                "ts": now,
                "event": "session_closed",
                "phase": phase_id,
                "terminal_state": canon,
                "terminal_class": t_class,
            }));
        }
        state.insert("updated_at".to_string(), json!(now));
        let state_val = Value::Object(state.clone());
        atomic_write_json(&sdir.join(format!("{sid}.json")), &state_val)?;
        let packet = build_phase_packet(&state, args.root);
        return Ok(json!({
            "advanced": true,
            "closed": true,
            "session": state_val,
            "packet": packet,
        }));
    }

    let blockers = blocking_requirements(&state);
    if !blockers.is_empty() {
        state.insert("updated_at".to_string(), json!(now));
        let state_val = Value::Object(state);
        atomic_write_json(&sdir.join(format!("{sid}.json")), &state_val)?;
        return Err(format!(
            "cannot advance past phase {phase_id:?}: {}",
            blockers.join("; ")
        ));
    }

    let next_idx = idx + 1;
    let next_phase = phases[next_idx]
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    state.insert("current_phase_index".to_string(), json!(next_idx));
    state.insert("current_phase".to_string(), json!(next_phase));
    if let Some(arr) = state
        .entry("history".to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
    {
        arr.push(json!({
            "ts": now,
            "event": "phase_advanced",
            "from_phase": phase_id,
            "to_phase": next_phase,
        }));
    }
    state.insert("updated_at".to_string(), json!(now));
    let state_val = Value::Object(state.clone());
    atomic_write_json(&sdir.join(format!("{sid}.json")), &state_val)?;
    let packet = build_phase_packet(&state, args.root);
    Ok(json!({
        "advanced": true,
        "closed": false,
        "from_phase": phase_id,
        "to_phase": next_phase,
        "session": state_val,
        "packet": packet,
    }))
}

pub fn benchmark_progressive_savings(root: &Path) -> Value {
    let missions = list_missions(root, None, None, true);
    let mut rows = Vec::new();
    let mut sum_red = 0.0f64;
    let mut all_within = true;
    for m in &missions {
        let phases = build_phase_plan(m);
        let mut max_tok = 0usize;
        let mut min_tok = usize::MAX;
        for (i, ph) in phases.iter().enumerate() {
            let pid = ph.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let stub_val = json!({
                "session_id": format!("bench-{}", m.name),
                "mission": m.name,
                "proof": m.proof,
                "status": "active",
                "goal": "benchmark progressive phase load",
                "base": "fleet/integration",
                "runtime": "auto",
                "current_phase_index": i,
                "current_phase": pid,
                "phases": phases,
                "approvals": {},
                "receipts": {},
                "full_activation_budget_tokens": m.activation_budget_tokens,
            });
            let pkt = build_phase_packet(stub_val.as_object().expect("obj"), root);
            let tok = pkt
                .get("token_budget")
                .and_then(|t| t.get("phase_tokens_est"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0) as usize;
            max_tok = max_tok.max(tok);
            min_tok = min_tok.min(tok);
        }
        if min_tok == usize::MAX {
            min_tok = 0;
        }
        let full = m.activation_budget_tokens.max(0) as usize;
        let reduction = if full > 0 {
            ((((full as f64) - (max_tok as f64)) / (full as f64)) * 1000.0).round() / 10.0
        } else {
            0.0
        };
        let within = max_tok < PHASE_TOKEN_CEILING;
        if !within {
            all_within = false;
        }
        sum_red += reduction;
        rows.push(json!({
            "mission": m.name,
            "full_budget_tokens": full,
            "max_phase_tokens": max_tok,
            "min_phase_tokens": min_tok,
            "within_5k_ceiling": within,
            "reduction_pct": reduction,
        }));
    }
    let avg_reduction = ((sum_red / rows.len().max(1) as f64) * 10.0).round() / 10.0;
    json!({
        "mission_count": rows.len(),
        "ceiling_tokens": PHASE_TOKEN_CEILING,
        "all_within_ceiling": all_within,
        "avg_reduction_pct": avg_reduction,
        "missions": rows,
    })
}
