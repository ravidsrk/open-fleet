//! Native zero-Python Model Context Protocol (MCP) JSON-RPC 2.0 stdio server
//! for open-fleet, supporting both newline-delimited JSON-RPC and Content-Length
//! LSP framing across MCP protocol versions 2025-03-26 and 2024-11-05.

use of_catalog::{
    build_launch_prompt, catalog_overview, catalog_version, certification_summary, get_mission,
    list_missions, load_capabilities, load_pins, load_quarantine, route_intent,
};
use of_floor::FloorConfig;
use of_install::doctor;
use of_ledgers::decisions_cli::read_lines;
use of_ledgers::egress::{load_ledger, sha256_hex};
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: &str = "2025-03-26";
pub const SUPPORTED_PROTOCOLS: &[&str] = &["2025-03-26", "2024-11-05"];

pub struct OpenFleetMcpServer {
    pub root: PathBuf,
    pub repo: PathBuf,
    pub version: String,
}

impl OpenFleetMcpServer {
    pub fn new(root: PathBuf, repo: PathBuf) -> Self {
        let version = catalog_version(&root);
        Self {
            root,
            repo,
            version,
        }
    }

    pub fn tool_definitions(&self) -> Vec<Value> {
        vec![
            json!({
                "name": "fleet_doctor",
                "description": "Diagnose environment readiness: git, catalog, installed coding-agent harnesses, and native hooks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Optional repository directory"}
                    }
                }
            }),
            json!({
                "name": "fleet_route_mission",
                "description": "Route a developer goal to the best-matching outcome mission with proof tier, token load, capabilities, and a ready-to-run prompt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "goal": {"type": "string", "description": "Natural-language description of the engineering outcome"},
                        "top_k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5}
                    },
                    "required": ["goal"]
                }
            }),
            json!({
                "name": "fleet_list_missions",
                "description": "List open-fleet missions with proof tier, autonomy level, activation token budget, and required capabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof": {"type": "string", "enum": ["external-run", "self-run", "doctrine-only"]},
                        "category": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_get_mission",
                "description": "Fetch a single mission's compact identity contract, composed playbooks, deferred reads, convergence proof, and launch prompt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string", "description": "Mission name (e.g. review-it, ship-it, clean-sweep)"},
                        "include_body": {"type": "boolean", "default": false}
                    },
                    "required": ["mission"]
                }
            }),
            json!({
                "name": "fleet_floor_check",
                "description": "Run the native Rust floor guard against a base ref to detect silenced checkers, weakened assertions, unfinished markers, or guard-surface edits.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string", "default": "origin/main"},
                        "repo": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_certification",
                "description": "Inspect the honest provider & harness certification matrix (live-witnessed vs fixture-tested vs source-only vs unsupported).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_decisions",
                "description": "Read recent durable gate decisions (mechanical, taste, one-way) from docs/DECISIONS.md.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30}
                    }
                }
            }),
            json!({
                "name": "fleet_egress_verify",
                "description": "Verify the content-free SHA-256 hash-chained egress receipt ledger (.orca/egress.jsonl) natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ledger": {"type": "string", "description": "Optional explicit ledger path"},
                        "repo": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_preflight",
                "description": "Run fail-closed native preflight checks for a mission on a target repository (capability check, quarantine check, non-default BASE guard).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string"},
                        "repo": {"type": "string"},
                        "mode": {"type": "string", "enum": ["readonly", "write"], "default": "readonly"},
                        "base": {"type": "string"},
                        "default": {"type": "string"},
                        "offline": {"type": "boolean", "default": false},
                        "runtime": {"type": "string", "default": "auto"}
                    },
                    "required": ["mission"]
                }
            }),
            json!({
                "name": "fleet_chain_check",
                "description": "Classify or gate a mission terminal state natively per mission-chaining.md (degraded/unknown stop fail-closed).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "terminal": {"type": "string"},
                        "allowed": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["terminal"]
                }
            }),
            json!({
                "name": "fleet_session_start",
                "description": "Start a progressive (<5K-token/phase) mission session with enforced receipts and human one-way gates.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string"},
                        "goal": {"type": "string"},
                        "base": {"type": "string", "default": ""},
                        "runtime": {"type": "string", "default": "auto"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"}
                    },
                    "required": ["mission", "goal"]
                }
            }),
            json!({
                "name": "fleet_session_list",
                "description": "List progressive mission sessions persisted for a repository.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_session_packet",
                "description": "Fetch the <5K-token active phase packet for a progressive mission session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"}
                    },
                    "required": ["session_id"]
                }
            }),
            json!({
                "name": "fleet_session_approve_gate",
                "description": "Record an explicit human approval for a one-way gate (freeze/promote); refuses non-human actor identities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "gate": {"type": "string"},
                        "actor": {"type": "string"},
                        "rationale": {"type": "string"},
                        "contract_digest": {"type": "string"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"}
                    },
                    "required": ["session_id", "gate", "actor", "rationale"]
                }
            }),
            json!({
                "name": "fleet_session_advance",
                "description": "Advance a progressive session by one phase (fail-closed on missing receipts, unapproved gates, or invalid terminals).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "receipt": {"type": "object"},
                        "terminal_state": {"type": "string"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"}
                    },
                    "required": ["session_id"]
                }
            }),
            json!({
                "name": "fleet_solo_review",
                "description": "Run the honest solo-developer verified review lane natively (diff_scope + floor_guard + irreversibility stop-list + build-blind review packet).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string", "default": "origin/main"},
                        "repo": {"type": "string"},
                        "lighting": {"type": "string", "enum": ["auto", "lit", "dark-eligible"], "default": "auto"},
                        "nc_command": {"type": "string"},
                        "builder": {"type": "string"},
                        "contract": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_readiness",
                "description": "Inspect the honest proof-graduation backlog and multi-harness certification readiness natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "check_cert": {"type": "boolean", "default": false}
                    }
                }
            }),
            json!({
                "name": "fleet_verify_manifest",
                "description": "Run native SHA-bound evidence verification (of_verify::verify) on a unit manifest with zero Python startup.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "manifest": {"type": "string"},
                        "base": {"type": "string"},
                        "repo": {"type": "string"},
                        "contract_source": {"type": "string"},
                        "contract_digest": {"type": "string"},
                        "unit_class": {"type": "string"},
                        "execute_nc": {"type": "boolean", "default": false},
                        "nc_command": {"type": "string"},
                        "no_gh": {"type": "boolean", "default": false},
                        "allow_static_nc": {"type": "boolean", "default": false}
                    },
                    "required": ["manifest", "base"]
                }
            }),
            json!({
                "name": "fleet_run_report_check",
                "description": "Check whether a run report binds to its RUN header, signed inventory, and signed verifier transcript natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "report": {"type": "string"},
                        "mission": {"type": "string"},
                        "tier": {"type": "string", "enum": ["self-run", "external-run"], "default": "self-run"},
                        "base": {"type": "string"},
                        "root": {"type": "string"}
                    },
                    "required": ["report", "mission"]
                }
            }),
            json!({
                "name": "fleet_events_report",
                "description": "Derive structured run metrics and WIP curves from an append-only .orca/events.jsonl ledger natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "log": {"type": "string"},
                        "run": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_diff_scope",
                "description": "Classify changed paths natively into SCOPE_* review lenses (no Python required).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string"},
                        "strict": {"type": "boolean", "default": false},
                        "repo": {"type": "string"}
                    },
                    "required": ["base"]
                }
            }),
            json!({
                "name": "fleet_quarantine_check",
                "description": "Check the catalog or one mission (with transitive playbook closure) against runtime/quarantine.json natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string", "description": "Optional mission name; omit to check the whole catalog"},
                        "root": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_proof_status",
                "description": "Summarize every mission's proof tier (doctrine-only / self-run / external-run) and verify proof_evidence containment natively.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "root": {"type": "string"}
                    }
                }
            }),
            json!({
                "name": "fleet_run_demo",
                "description": "Run the negative-control proof demo (self-scoring GREEN vs verify.py RED).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["negative-control", "first-run"], "default": "negative-control"}
                    }
                }
            }),
        ]
    }

    pub fn resource_definitions(&self) -> Vec<Value> {
        vec![
            json!({
                "uri": "open-fleet://catalog/overview",
                "name": "Catalog Overview",
                "description": "Proof ladder rollup, mission count, quarantine state, and upstream pins.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://catalog/missions",
                "name": "Mission Catalog",
                "description": "All discoverable outcome-named missions with six-point identity contracts.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://runtime/capabilities",
                "name": "Runtime Capabilities Matrix",
                "description": "RPI capabilities, providers, harnesses, and per-mission capability requirements.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://runtime/certification",
                "name": "Provider & Harness Certification",
                "description": "Honest per-cell certification tiers backed by bound run evidence.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://runtime/pins",
                "name": "Upstream Pins",
                "description": "Pinned commits and witness dates for Orca and upstream methodology packs.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://runtime/quarantine",
                "name": "Component Quarantine Registry",
                "description": "Human-controlled fail-closed deny-list of quarantined components.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "open-fleet://governance/decisions",
                "name": "Durable Decision Ledger",
                "description": "Parsed mechanical, taste, and one-way gate decisions from docs/DECISIONS.md.",
                "mimeType": "application/json"
            }),
        ]
    }

    pub fn prompt_definitions(&self) -> Vec<Value> {
        list_missions(&self.root, None, None, false)
            .into_iter()
            .map(|m| {
                json!({
                    "name": format!("mission/{}", m.name),
                    "description": format!("[{}] {}", m.proof, m.summary),
                    "arguments": [{
                        "name": "goal",
                        "description": "Bounded engineering goal, issue, or PR URL",
                        "required": true
                    }]
                })
            })
            .collect()
    }

    fn read_decisions_json(&self, repo: &Path, limit: usize) -> Value {
        let log_path = repo.join("docs/DECISIONS.md");
        if !log_path.is_file() {
            return json!({
                "exists": false,
                "path": log_path.display().to_string(),
                "total": 0,
                "entries": [],
            });
        }
        match read_lines(&log_path) {
            Ok(rows) => {
                let total = rows.len();
                let start = total.saturating_sub(limit);
                let entries: Vec<Value> = rows[start..]
                    .iter()
                    .rev()
                    .map(|(lineno, r)| {
                        json!({
                            "lineno": lineno,
                            "ts": r.ts,
                            "id": r.id,
                            "class": r.class,
                            "answer": r.answer,
                            "why": r.why,
                            "task_id": r.task_id,
                        })
                    })
                    .collect();
                json!({
                    "exists": true,
                    "path": log_path.display().to_string(),
                    "total": total,
                    "entries": entries,
                })
            }
            Err(err) => json!({
                "exists": true,
                "path": log_path.display().to_string(),
                "error": err,
                "total": 0,
                "entries": [],
            }),
        }
    }

    pub fn read_resource(&self, uri: &str) -> Result<Value, String> {
        let payload = if uri == "open-fleet://catalog/overview" {
            catalog_overview(&self.root)
        } else if uri == "open-fleet://catalog/missions" {
            serde_json::to_value(list_missions(&self.root, None, None, false))
                .unwrap_or_else(|_| json!([]))
        } else if let Some(name) = uri.strip_prefix("open-fleet://catalog/mission/") {
            let trimmed = name.trim();
            let Some(m) = get_mission(&self.root, trimmed) else {
                return Err(format!("unknown mission: {trimmed}"));
            };
            serde_json::to_value(m).unwrap_or_else(|_| json!({}))
        } else if uri == "open-fleet://runtime/capabilities" {
            load_capabilities(&self.root)
        } else if uri == "open-fleet://runtime/certification" {
            certification_summary(&self.root)
        } else if uri == "open-fleet://runtime/pins" {
            load_pins(&self.root)
        } else if uri == "open-fleet://runtime/quarantine" {
            load_quarantine(&self.root)
        } else if uri == "open-fleet://governance/decisions" {
            self.read_decisions_json(&self.repo, 100)
        } else {
            return Err(format!("unknown resource URI: {uri}"));
        };
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()),
            }]
        }))
    }

    pub fn get_prompt(&self, name: &str, arguments: Option<&Value>) -> Result<Value, String> {
        let mission_name = name.strip_prefix("mission/").unwrap_or(name);
        let Some(mission) = get_mission(&self.root, mission_name) else {
            return Err(format!("unknown prompt: {name}"));
        };
        let goal = arguments
            .and_then(|a| a.get("goal"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let text = build_launch_prompt(&mission, goal);
        Ok(json!({
            "description": format!("Launch prompt for {} ({})", mission.name, mission.proof),
            "messages": [{
                "role": "user",
                "content": {"type": "text", "text": text}
            }]
        }))
    }

    pub fn call_tool(&self, name: &str, arguments: Option<&Value>) -> Result<Value, String> {
        let empty = json!({});
        let args = arguments.filter(|v| v.is_object()).unwrap_or(&empty);
        let mut is_error = false;

        let result: Value = match name {
            "fleet_doctor" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let rep = doctor(&repo, env!("CARGO_PKG_VERSION"));
                serde_json::to_value(rep).unwrap_or_else(|_| json!({}))
            }
            "fleet_route_mission" => {
                let goal = args
                    .get("goal")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if goal.is_empty() {
                    is_error = true;
                    json!({"error": "goal is required"})
                } else {
                    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
                    serde_json::to_value(route_intent(&self.root, goal, top_k))
                        .unwrap_or_else(|_| json!({}))
                }
            }
            "fleet_list_missions" => {
                let proof = args.get("proof").and_then(|v| v.as_str());
                let category = args.get("category").and_then(|v| v.as_str());
                serde_json::to_value(list_missions(&self.root, proof, category, false))
                    .unwrap_or_else(|_| json!([]))
            }
            "fleet_get_mission" => {
                let mname = args
                    .get("mission")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let include_body = args
                    .get("include_body")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                match get_mission(&self.root, mname) {
                    Some(mut m) => {
                        if !include_body {
                            m.body = None;
                        }
                        serde_json::to_value(m).unwrap_or_else(|_| json!({}))
                    }
                    None => {
                        is_error = true;
                        json!({"error": format!("unknown mission: {mname}")})
                    }
                }
            }
            "fleet_floor_check" => {
                let base = args
                    .get("base")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let cfg = FloorConfig {
                    base,
                    constraints: "CONSTRAINTS.md".to_string(),
                    waivers: "docs/DECISIONS.md".to_string(),
                    repo,
                    quiet: true,
                    json: true,
                };
                // Execute native Rust floor engine directly in-process!
                let out = of_floor::evaluate(&cfg);
                is_error = out.exit_code != 0;
                serde_json::to_value(&out).unwrap_or_else(|_| json!({}))
            }
            "fleet_certification" => {
                let mut summary = certification_summary(&self.root);
                if let Some(provider) = args.get("provider").and_then(|v| v.as_str()) {
                    if let Some(arr) = summary.get("providers").and_then(|v| v.as_array()).cloned()
                    {
                        let filtered: Vec<Value> = arr
                            .into_iter()
                            .filter(|p| p.get("name").and_then(|n| n.as_str()) == Some(provider))
                            .collect();
                        if let Some(obj) = summary.as_object_mut() {
                            obj.insert("providers".to_string(), Value::Array(filtered));
                        }
                    }
                }
                summary
            }
            "fleet_decisions" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(30) as usize;
                self.read_decisions_json(&repo, limit)
            }
            "fleet_egress_verify" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let ledger = args
                    .get("ledger")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| repo.join(".orca/egress.jsonl"));
                match load_ledger(&ledger) {
                    Ok(loaded) => {
                        if let Some(broken) = loaded.scan.broken_line {
                            is_error = true;
                            json!({
                                "ok": false,
                                "exists": loaded.exists,
                                "ledger": ledger.display().to_string(),
                                "broken_line": broken,
                                "reason": loaded.scan.reason,
                                "lines_read": loaded.scan.lines_read,
                            })
                        } else {
                            let head = loaded
                                .scan
                                .receipts
                                .last()
                                .map(|(_, raw, _)| sha256_hex(raw))
                                .unwrap_or_else(|| "(empty)".to_string());
                            json!({
                                "ok": true,
                                "exists": loaded.exists,
                                "ledger": ledger.display().to_string(),
                                "receipts": loaded.scan.receipts.len(),
                                "head": head,
                            })
                        }
                    }
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_preflight" => {
                let mission = args
                    .get("mission")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let mode = args
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("readonly")
                    .to_string();
                let runtime = args
                    .get("runtime")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto")
                    .to_string();
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let pf_args = of_verify::preflight::PreflightArgs {
                    base: args
                        .get("base")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    default_branch: args
                        .get("default")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    fork_point: None,
                    mode,
                    require_gitleaks: false,
                    offline: args
                        .get("offline")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    mission,
                    runtime: Some(runtime),
                    strict_native: false,
                    json: true,
                    cwd: Some(repo),
                    catalog_root: Some(self.root.clone()),
                };
                let (code, payload, _, _) = of_verify::preflight::evaluate(&pf_args);
                is_error = code != 0;
                payload
            }
            "fleet_chain_check" => {
                let terminal = args.get("terminal").and_then(|v| v.as_str()).unwrap_or("");
                let canon = of_verify::chain_check::canonical(terminal);
                let cls = of_verify::chain_check::classify(terminal);
                if let Some(arr) = args.get("allowed").and_then(|v| v.as_array()) {
                    let allowed: std::collections::BTreeSet<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    let (proceed, why) = of_verify::chain_check::gate(terminal, &allowed);
                    is_error = !proceed;
                    json!({
                        "terminal": terminal,
                        "canonical": canon,
                        "class": cls,
                        "proceed": proceed,
                        "reason": why,
                    })
                } else {
                    is_error = cls == "unknown";
                    json!({
                        "terminal": terminal,
                        "canonical": canon,
                        "class": cls,
                    })
                }
            }
            "fleet_session_start" => {
                let mission = args.get("mission").and_then(|v| v.as_str()).unwrap_or("");
                let goal = args.get("goal").and_then(|v| v.as_str()).unwrap_or("");
                let base = args.get("base").and_then(|v| v.as_str()).unwrap_or("");
                let runtime = args
                    .get("runtime")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto");
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sdir = args
                    .get("sessions_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                match of_verify::sessions::start_session(&of_verify::sessions::StartSessionArgs {
                    mission,
                    goal,
                    root: &self.root,
                    repo: &repo,
                    sessions_dir: sdir.as_deref(),
                    base_branch: base,
                    runtime,
                }) {
                    Ok(v) => v,
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_session_list" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sdir = args
                    .get("sessions_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                json!({
                    "sessions": of_verify::sessions::list_sessions(&repo, sdir.as_deref()),
                })
            }
            "fleet_session_packet" => {
                let sid = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sdir = args
                    .get("sessions_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                match of_verify::sessions::load_session(sid, &repo, sdir.as_deref()) {
                    Ok(st) => of_verify::sessions::build_phase_packet(&st, &self.root),
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_session_approve_gate" => {
                let sid = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let gate = args.get("gate").and_then(|v| v.as_str()).unwrap_or("");
                let actor = args.get("actor").and_then(|v| v.as_str()).unwrap_or("");
                let rationale = args.get("rationale").and_then(|v| v.as_str()).unwrap_or("");
                let digest = args
                    .get("contract_digest")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sdir = args
                    .get("sessions_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                match of_verify::sessions::approve_gate(&of_verify::sessions::ApproveGateArgs {
                    session_id: sid,
                    gate,
                    actor,
                    rationale,
                    contract_digest: digest,
                    root: &self.root,
                    repo: &repo,
                    sessions_dir: sdir.as_deref(),
                }) {
                    Ok(v) => v,
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_session_advance" => {
                let sid = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let receipt = args.get("receipt").and_then(|v| v.as_object()).cloned();
                let term = args
                    .get("terminal_state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sdir = args
                    .get("sessions_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
                match of_verify::sessions::advance_session(
                    &of_verify::sessions::AdvanceSessionArgs {
                        session_id: sid,
                        receipt,
                        terminal_state: term,
                        root: &self.root,
                        repo: &repo,
                        sessions_dir: sdir.as_deref(),
                    },
                ) {
                    Ok(v) => v,
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_solo_review" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.repo.clone());
                let sr_args = of_verify::solo_review::SoloReviewArgs {
                    base: args
                        .get("base")
                        .and_then(|v| v.as_str())
                        .unwrap_or("origin/main")
                        .to_string(),
                    root: self.root.clone(),
                    repo,
                    contract_path: args
                        .get("contract")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    builder_harness: args
                        .get("builder")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    manifest: String::new(),
                    lighting: args
                        .get("lighting")
                        .and_then(|v| v.as_str())
                        .unwrap_or("auto")
                        .to_string(),
                    nc_command: args
                        .get("nc_command")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    no_gh: true,
                    transcript_out: String::new(),
                    transcript_key: String::new(),
                    packet_out: String::new(),
                };
                match of_verify::solo_review::run_solo_review(&sr_args) {
                    Ok(v) => {
                        is_error = !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                        v
                    }
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": err})
                    }
                }
            }
            "fleet_readiness" => {
                let check_cert = args
                    .get("check_cert")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let rep = of_verify::readiness::readiness_report(
                    &self.root,
                    env!("CARGO_PKG_VERSION"),
                    check_cert,
                );
                if let Some(cc) = rep.get("certification_check").and_then(|v| v.as_object()) {
                    is_error = !cc.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                }
                rep
            }
            "fleet_verify_manifest" => {
                let manifest = args.get("manifest").and_then(|v| v.as_str()).unwrap_or("");
                let base = args.get("base").and_then(|v| v.as_str()).unwrap_or("");
                if manifest.is_empty() || base.is_empty() {
                    is_error = true;
                    json!({"error": "manifest and base are required"})
                } else {
                    let repo = args
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| self.repo.clone());
                    let m_path = {
                        let p = PathBuf::from(manifest);
                        if p.is_absolute() {
                            p
                        } else {
                            repo.join(p)
                        }
                    };
                    let repo_s = repo.display().to_string();
                    let v_args = of_verify::verify::VerifyArgs {
                        manifest: m_path.display().to_string(),
                        base: Some(base.to_string()),
                        contract_source: args
                            .get("contract_source")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        contract_digest: args
                            .get("contract_digest")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        unit_class: args
                            .get("unit_class")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        execute_nc: args
                            .get("execute_nc")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        nc_command: args
                            .get("nc_command")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        no_gh: args.get("no_gh").and_then(|v| v.as_bool()).unwrap_or(false),
                        allow_static_nc: args
                            .get("allow_static_nc")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        git_dir: Some(repo_s.clone()),
                        evidence_root: Some(repo_s),
                        ..Default::default()
                    };
                    let (code, payload) = of_verify::verify::verify_manifest_json(&v_args);
                    is_error = code != 0;
                    payload
                }
            }
            "fleet_run_report_check" => {
                let report = args.get("report").and_then(|v| v.as_str()).unwrap_or("");
                let mission = args.get("mission").and_then(|v| v.as_str()).unwrap_or("");
                if report.is_empty() || mission.is_empty() {
                    is_error = true;
                    json!({"error": "report and mission are required"})
                } else {
                    let tier = args
                        .get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("self-run");
                    let base = args.get("base").and_then(|v| v.as_str());
                    let root = args
                        .get("root")
                        .and_then(|v| v.as_str())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| self.root.clone());
                    let errors =
                        of_verify::run_report::check_report(report, mission, tier, &root, base);
                    is_error = !errors.is_empty();
                    json!({
                        "ok": errors.is_empty(),
                        "report": report,
                        "mission": mission,
                        "tier": tier,
                        "errors": errors,
                    })
                }
            }
            "fleet_events_report" => {
                let log = args
                    .get("log")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| of_ledgers::events::log_path(None));
                let run = args.get("run").and_then(|v| v.as_str());
                match of_ledgers::events::read_log(&log) {
                    Ok((events, file_sha, head)) => {
                        match of_ledgers::events::derive(&events, run, &file_sha, &head) {
                            Ok(report) => report,
                            Err(err) => {
                                is_error = true;
                                json!({"ok": false, "error": format!("{err:?}")})
                            }
                        }
                    }
                    Err(err) => {
                        is_error = true;
                        json!({"ok": false, "error": format!("{err:?}")})
                    }
                }
            }
            "fleet_diff_scope" => {
                let base = args.get("base").and_then(|v| v.as_str()).unwrap_or("");
                if base.is_empty() {
                    is_error = true;
                    json!({"error": "base is required"})
                } else {
                    let repo = args
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| self.repo.clone());
                    let strict = args
                        .get("strict")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let (code, payload) =
                        of_verify::diff_scope::scope_to_json(&repo, Some(base), strict);
                    is_error = code != 0;
                    payload
                }
            }
            "fleet_quarantine_check" => {
                let root = args
                    .get("root")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.root.clone());
                let mission = args
                    .get("mission")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty());
                let (entries, errors, present) = of_verify::quarantine::load_quarantine(&root);
                if !errors.is_empty() {
                    is_error = true;
                    json!({"ok": false, "present": present, "errors": errors, "violations": []})
                } else if !present {
                    json!({"ok": true, "present": false, "violations": []})
                } else {
                    let view_res = match mission {
                        Some(m) => of_verify::quarantine::mission_view(&root, m),
                        None => of_verify::quarantine::catalog_view(&root).map(|mut v| {
                            v.missions.clear();
                            v
                        }),
                    };
                    match view_res {
                        Ok(v) => {
                            let found = of_verify::quarantine::violations(&entries, &v);
                            is_error = !found.is_empty();
                            json!({
                                "ok": found.is_empty(),
                                "present": true,
                                "violations": found,
                            })
                        }
                        Err(err) => {
                            is_error = true;
                            json!({"ok": false, "present": true, "errors": [err], "violations": []})
                        }
                    }
                }
            }
            "fleet_proof_status" => {
                let root = args
                    .get("root")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.root.clone());
                let skills_dir = root.join("skills");
                if !skills_dir.is_dir() {
                    is_error = true;
                    json!({"error": format!("no skills/ directory under {}", root.display())})
                } else {
                    let records = of_verify::proof_status::collect(&skills_dir, &root);
                    let rollup = of_verify::proof_status::rollup(&records);
                    let failures = of_verify::proof_status::check_failures(&records);
                    is_error = !failures.is_empty();
                    json!({
                        "ok": failures.is_empty(),
                        "rollup": rollup,
                        "missions": of_verify::proof_status::json_records(&records),
                    })
                }
            }
            "fleet_run_demo" => {
                let res = of_verify::demo::run_negative_control_demo();
                is_error = !res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                res
            }
            other => return Err(format!("unknown tool: {other}")),
        };

        let structured = if result.is_object() {
            result.clone()
        } else {
            json!({"items": result})
        };
        Ok(json!({
            "content": [{"type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())}],
            "structuredContent": structured,
            "isError": is_error,
        }))
    }

    pub fn handle_message(&self, msg: &Value) -> Option<Value> {
        let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let req_id = msg.get("id");
        let params = msg.get("params");

        if req_id.is_none()
            && matches!(
                method,
                "notifications/initialized" | "notifications/cancelled" | "initialized"
            )
        {
            return None;
        }
        let id_val = req_id.cloned().unwrap_or(Value::Null);
        let ok = |res: Value| Some(json!({"jsonrpc": "2.0", "id": id_val, "result": res}));
        let err = |code: i64, message: String| {
            Some(
                json!({"jsonrpc": "2.0", "id": id_val, "error": {"code": code, "message": message}}),
            )
        };

        match method {
            "initialize" => {
                let requested = params
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(PROTOCOL_VERSION);
                let chosen = if SUPPORTED_PROTOCOLS.contains(&requested) {
                    requested
                } else {
                    PROTOCOL_VERSION
                };
                ok(json!({
                    "protocolVersion": chosen,
                    "capabilities": {
                        "tools": {"listChanged": false},
                        "resources": {"subscribe": false, "listChanged": false},
                        "prompts": {"listChanged": false},
                    },
                    "serverInfo": {
                        "name": "open-fleet",
                        "version": self.version,
                    },
                    "instructions": "open-fleet native Rust MCP control plane: route goals to outcome missions with fleet_route_mission, check floor discipline with fleet_floor_check, verify egress receipts with fleet_egress_verify, and inspect certification and decisions natively.",
                }))
            }
            "ping" => ok(json!({})),
            "tools/list" => ok(json!({"tools": self.tool_definitions()})),
            "tools/call" => {
                let tool_name = params
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tool_args = params.and_then(|p| p.get("arguments"));
                match self.call_tool(tool_name, tool_args) {
                    Ok(res) => ok(res),
                    Err(msg) => err(-32602, msg),
                }
            }
            "resources/list" => ok(json!({"resources": self.resource_definitions()})),
            "resources/read" => {
                let uri = params
                    .and_then(|p| p.get("uri"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match self.read_resource(uri) {
                    Ok(res) => ok(res),
                    Err(msg) => err(-32602, msg),
                }
            }
            "prompts/list" => ok(json!({"prompts": self.prompt_definitions()})),
            "prompts/get" => {
                let pname = params
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pargs = params.and_then(|p| p.get("arguments"));
                match self.get_prompt(pname, pargs) {
                    Ok(res) => ok(res),
                    Err(msg) => err(-32602, msg),
                }
            }
            _ => err(-32601, format!("Method not found: {method}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FramingMode {
    Jsonl,
    Lsp,
}

fn read_framed_message<R: BufRead>(reader: &mut R) -> Result<Option<(Value, FramingMode)>, String> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let length: usize = rest
                .trim()
                .parse()
                .map_err(|_| format!("invalid Content-Length: {rest}"))?;
            // Consume remaining headers until empty line
            loop {
                line.clear();
                let hn = reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if hn == 0 || line.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).map_err(|e| e.to_string())?;
            let val: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            return Ok(Some((val, FramingMode::Lsp)));
        }
        let val: Value = serde_json::from_str(trimmed).map_err(|e| e.to_string())?;
        return Ok(Some((val, FramingMode::Jsonl)));
    }
}

fn write_framed_message<W: Write>(
    writer: &mut W,
    payload: &Value,
    mode: FramingMode,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    match mode {
        FramingMode::Lsp => {
            write!(writer, "Content-Length: {}\r\n\r\n", encoded.len())?;
            writer.write_all(&encoded)?;
        }
        FramingMode::Jsonl => {
            writer.write_all(&encoded)?;
            writer.write_all(b"\n")?;
        }
    }
    writer.flush()
}

pub fn serve_stdio(server: &OpenFleetMcpServer) -> i32 {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    loop {
        match read_framed_message(&mut reader) {
            Ok(None) => return 0,
            Ok(Some((msg, mode))) => {
                if let Some(resp) = server.handle_message(&msg) {
                    if write_framed_message(&mut writer, &resp, mode).is_err() {
                        return 0;
                    }
                }
            }
            Err(err) => {
                let payload = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32700, "message": format!("parse error: {err}")},
                });
                let _ = write_framed_message(&mut writer, &payload, FramingMode::Jsonl);
            }
        }
    }
}
