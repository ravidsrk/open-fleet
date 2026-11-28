//! Native zero-Python HTTP + SSE Mission Control server (`open-fleet ui`).
//!
//! Uses only Rust's standard library (`std::net::TcpListener`, `std::thread`)
//! and composes `of-catalog`, `of-install`, `of-ledgers`, `of-verify`, and
//! `of-mcp` directly in-process — zero Python runtime and zero external HTTP
//! crate dependencies.

use of_catalog::{
    catalog_overview, certification_summary, get_mission, list_missions, load_one_way_doors,
    load_retained_runs, route_intent,
};
use of_install::{doctor, embedded, install, InstallConfig, HARNESS_PROFILES};
use of_ledgers::decisions_cli::read_lines;
use of_mcp::OpenFleetMcpServer;
use of_verify::ci_check::render_workflow_snippet;
use of_verify::demo::run_negative_control_demo;
use of_verify::readiness::{readiness_report, run_negative_probes};
use of_verify::sessions::{
    advance_session, approve_gate, benchmark_progressive_savings, build_phase_packet,
    list_sessions, load_session, start_session, AdvanceSessionArgs, ApproveGateArgs,
    StartSessionArgs,
};
use of_verify::solo_review::{run_solo_review, SoloReviewArgs};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_POST_BYTES: usize = 16 * 1024;

pub struct MissionControlApp {
    pub root: PathBuf,
    pub repo: PathBuf,
    pub engine_version: String,
    mcp: OpenFleetMcpServer,
    demo_lock: Mutex<()>,
}

impl MissionControlApp {
    pub fn new(root: PathBuf, repo: PathBuf, engine_version: String) -> Self {
        let mcp = OpenFleetMcpServer::new(root.clone(), repo.clone());
        Self {
            root,
            repo,
            engine_version,
            mcp,
            demo_lock: Mutex::new(()),
        }
    }

    pub fn index_html(&self) -> Vec<u8> {
        let on_disk = self.root.join("open_fleet/ui_assets/index.html");
        if let Ok(bytes) = fs::read(&on_disk) {
            return bytes;
        }
        if let Some(bytes) = embedded::embedded_file("open_fleet/ui_assets/index.html") {
            return bytes.to_vec();
        }
        b"<!doctype html><html><head><title>open-fleet Mission Control</title></head><body><h1>open-fleet Mission Control</h1></body></html>\n".to_vec()
    }

    fn read_decisions_summary(&self, limit: usize) -> Value {
        let path = self.repo.join("docs/DECISIONS.md");
        if !path.is_file() {
            return json!({
                "exists": false,
                "path": path.to_string_lossy(),
                "total": 0,
                "entries": [],
            });
        }
        let entries = read_lines(&path).unwrap_or_default();
        let total = entries.len();
        let tail: Vec<Value> = entries
            .iter()
            .rev()
            .take(limit)
            .map(|(lineno, d)| {
                json!({
                    "lineno": lineno,
                    "ts": d.ts,
                    "id": d.id,
                    "class": d.class,
                    "answer": d.answer,
                    "why": d.why,
                    "task_id": d.task_id,
                })
            })
            .collect();
        json!({
            "exists": true,
            "path": path.to_string_lossy(),
            "total": total,
            "entries": tail,
        })
    }

    fn workspace_status(&self) -> Value {
        let db_path = self.repo.join(".orca/runtime.db");
        let events_path = self.repo.join(".orca/events.jsonl");
        let egress_path = self.repo.join(".orca/egress.jsonl");
        let count_lines = |p: &Path| -> usize {
            fs::read_to_string(p)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0)
        };
        let decisions = self.read_decisions_summary(30);
        json!({
            "repo": self.repo.to_string_lossy(),
            "runtime_state": {
                "db_path": db_path.to_string_lossy(),
                "db_exists": db_path.is_file(),
                "summary": {
                    "runs": 0,
                    "tasks_total": 0,
                    "active_dispatches": 0,
                    "open_gates": 0,
                    "queued_merges": 0,
                }
            },
            "events": {
                "path": events_path.to_string_lossy(),
                "count": count_lines(&events_path),
            },
            "egress": {
                "path": egress_path.to_string_lossy(),
                "count": count_lines(&egress_path),
            },
            "decisions": decisions,
        })
    }

    fn build_mcp_snippet(&self, host: &str, runtime: &str) -> Value {
        let bin = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "open-fleet".to_string());
        let profile = HARNESS_PROFILES
            .iter()
            .find(|p| p.id == host)
            .unwrap_or(&HARNESS_PROFILES[0]);
        let content = if host == "codex" {
            format!(
                "[mcp_servers.open-fleet]\ncommand = \"{bin}\"\nargs = [\"mcp\"]\n[mcp_servers.open-fleet.env]\nOPEN_FLEET_RUNTIME = \"{runtime}\"\n"
            )
        } else {
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "open-fleet": {
                        "command": bin,
                        "args": ["mcp"],
                        "env": {
                            "OPEN_FLEET_RUNTIME": runtime
                        }
                    }
                }
            }))
            .unwrap_or_else(|_| "{}".to_string())
        };
        json!({
            "host": host,
            "config_path": profile.mcp_rel,
            "content": content,
            "written": false,
        })
    }

    pub fn handle_get(
        &self,
        path: &str,
        query: &HashMap<String, String>,
    ) -> (u16, &'static str, Vec<u8>) {
        if path == "/" || path == "/index.html" {
            return (200, "text/html; charset=utf-8", self.index_html());
        }
        if path == "/api/health" {
            return json_resp(
                200,
                &json!({
                    "ok": true,
                    "engine": "rust",
                    "version": self.engine_version,
                    "root": self.root.to_string_lossy(),
                    "repo": self.repo.to_string_lossy(),
                }),
            );
        }
        if path == "/api/overview" {
            let tools: Vec<Value> = self
                .mcp
                .tool_definitions()
                .into_iter()
                .map(|t| {
                    json!({
                        "name": t.get("name").cloned().unwrap_or(Value::Null),
                        "description": t.get("description").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            return json_resp(
                200,
                &json!({
                    "catalog": catalog_overview(&self.root),
                    "doctor": doctor(&self.repo, &self.engine_version),
                    "workspace": self.workspace_status(),
                    "one_way_doors": load_one_way_doors(&self.root),
                    "mcp_tools": tools,
                    "mcp_resources": self.mcp.resource_definitions(),
                }),
            );
        }
        if path == "/api/doctor" {
            return json_resp(
                200,
                &serde_json::to_value(doctor(&self.repo, &self.engine_version))
                    .unwrap_or_else(|_| json!({})),
            );
        }
        if path == "/api/missions" {
            let proof = query
                .get("proof")
                .map(|s| s.as_str())
                .filter(|s| !s.is_empty());
            let category = query
                .get("category")
                .map(|s| s.as_str())
                .filter(|s| !s.is_empty());
            let missions = list_missions(&self.root, proof, category, false);
            return json_resp(200, &json!({"missions": missions}));
        }
        if let Some(raw_name) = path.strip_prefix("/api/missions/") {
            let name = percent_decode(raw_name).trim().to_string();
            return match get_mission(&self.root, &name) {
                Some(m) => json_resp(200, &serde_json::to_value(m).unwrap_or_else(|_| json!({}))),
                None => json_resp(404, &json!({"error": format!("unknown mission: {name}")})),
            };
        }
        if path == "/api/route" {
            let goal = query.get("q").map(|s| s.as_str()).unwrap_or("");
            let top_k = query
                .get("top")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5)
                .clamp(1, 10);
            let res = route_intent(&self.root, goal, top_k);
            return json_resp(
                200,
                &serde_json::to_value(res).unwrap_or_else(|_| json!({})),
            );
        }
        if path == "/api/certification" {
            return json_resp(200, &certification_summary(&self.root));
        }
        if path == "/api/runs" {
            return json_resp(200, &json!({"runs": load_retained_runs(&self.root)}));
        }
        if path == "/api/state" {
            return json_resp(200, &self.workspace_status());
        }
        if path == "/api/decisions" {
            return json_resp(200, &self.read_decisions_summary(100));
        }
        if path == "/api/sessions" {
            return json_resp(
                200,
                &json!({
                    "sessions": list_sessions(&self.repo, None),
                    "benchmark": benchmark_progressive_savings(&self.root),
                }),
            );
        }
        if let Some(raw_sid) = path.strip_prefix("/api/sessions/") {
            let sid = percent_decode(raw_sid).trim().to_string();
            return match load_session(&sid, &self.repo, None) {
                Ok(st) => {
                    let pkt = build_phase_packet(&st, &self.root);
                    json_resp(200, &json!({"session": st, "packet": pkt}))
                }
                Err(err) => json_resp(404, &json!({"error": err})),
            };
        }
        if path == "/api/readiness" {
            return json_resp(
                200,
                &readiness_report(&self.root, &self.engine_version, false),
            );
        }
        if path == "/api/ci-workflow" {
            let base = query.get("base").map(|s| s.as_str()).unwrap_or("main");
            let inc_manifest = query
                .get("manifest")
                .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            return json_resp(
                200,
                &json!({
                    "action_path": ".github/actions/open-fleet-verify/action.yml",
                    "workflow_yaml": render_workflow_snippet(base, inc_manifest),
                }),
            );
        }
        if path == "/api/setup/preview" {
            let host = query.get("host").map(|s| s.as_str()).unwrap_or("claude");
            let runtime = query.get("runtime").map(|s| s.as_str()).unwrap_or("auto");
            let Some(profile) = HARNESS_PROFILES.iter().find(|p| p.id == host) else {
                return json_resp(400, &json!({"error": format!("unknown host: {host}")}));
            };
            let runtime_clean = match runtime {
                "auto" | "posix" | "orca" | "overstory" | "t3code" | "superset" | "worktrunk" => {
                    runtime
                }
                _ => "auto",
            };
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let preview = match install(&InstallConfig {
                harness: host.to_string(),
                scope: "user".to_string(),
                mode: "symlink".to_string(),
                home,
                repo: self.repo.clone(),
                with_hooks: profile.supports_hooks,
                dry_run: true,
                json: true,
            }) {
                Ok(rep) => serde_json::to_value(rep).unwrap_or_else(|_| json!({})),
                Err(err) => json!({"error": err, "targets": []}),
            };
            let cli_cmd = if profile.supports_hooks {
                format!("open-fleet init --harness {host} --with-hooks")
            } else {
                format!("open-fleet init --harness {host}")
            };
            return json_resp(
                200,
                &json!({
                    "host": host,
                    "profile": {
                        "id": profile.id,
                        "label": profile.label,
                        "skills_rel": profile.skills_rel,
                        "mcp_rel": profile.mcp_rel,
                        "supports_hooks": profile.supports_hooks,
                        "invocation": profile.invocation,
                    },
                    "runtime": runtime_clean,
                    "cli_command": cli_cmd,
                    "mcp": self.build_mcp_snippet(host, runtime_clean),
                    "preview": preview,
                }),
            );
        }
        json_resp(404, &json!({"error": format!("not found: {path}")}))
    }

    pub fn handle_post(&self, path: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
        if body.len() > MAX_POST_BYTES {
            return json_resp(413, &json!({"error": "request body too large"}));
        }
        let payload: Map<String, Value> = if body.iter().all(|b| b.is_ascii_whitespace()) {
            Map::new()
        } else {
            match serde_json::from_slice::<Value>(body) {
                Ok(Value::Object(map)) => map,
                Ok(_) => return json_resp(400, &json!({"error": "JSON body must be an object"})),
                Err(_) => return json_resp(400, &json!({"error": "invalid JSON body"})),
            }
        };

        let get_str = |k: &str| -> String {
            payload
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };

        if path == "/api/route" {
            let goal = get_str("goal");
            let top_k = payload
                .get("top_k")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(5)
                .clamp(1, 10);
            let res = route_intent(&self.root, &goal, top_k);
            return json_resp(
                200,
                &serde_json::to_value(res).unwrap_or_else(|_| json!({})),
            );
        }

        if path == "/api/demo/negative-control" {
            let Ok(_guard) = self.demo_lock.try_lock() else {
                return json_resp(
                    429,
                    &json!({"error": "a verification demo is already running"}),
                );
            };
            return json_resp(200, &run_negative_control_demo());
        }

        if path == "/api/preflight" {
            let mission = {
                let m = get_str("mission");
                if m.is_empty() {
                    "review-it".to_string()
                } else {
                    m
                }
            };
            let runtime = {
                let r = get_str("runtime");
                if r.is_empty() {
                    "posix".to_string()
                } else {
                    r
                }
            };
            let known: Vec<String> = list_missions(&self.root, None, None, false)
                .into_iter()
                .map(|m| m.name)
                .collect();
            if !known.iter().any(|k| k == &mission) {
                return json_resp(
                    400,
                    &json!({"error": format!("unknown mission: {mission}")}),
                );
            }
            if !matches!(
                runtime.as_str(),
                "auto" | "posix" | "orca" | "overstory" | "t3code" | "superset" | "worktrunk"
            ) {
                return json_resp(
                    400,
                    &json!({"error": format!("unsupported runtime: {runtime}")}),
                );
            }
            let tool_args = json!({
                "mission": mission,
                "mode": "readonly",
                "runtime": runtime,
                "repo": self.repo.to_string_lossy(),
            });
            return match self.mcp.call_tool("fleet_preflight", Some(&tool_args)) {
                Ok(out) => json_resp(200, out.get("structuredContent").unwrap_or(&out)),
                Err(err) => json_resp(500, &json!({"error": err})),
            };
        }

        if path == "/api/sessions" {
            let mission = get_str("mission");
            let goal = get_str("goal");
            let base = get_str("base");
            let runtime = {
                let r = get_str("runtime");
                if r.is_empty() {
                    "auto".to_string()
                } else {
                    r
                }
            };
            return match start_session(&StartSessionArgs {
                mission: &mission,
                goal: &goal,
                root: &self.root,
                repo: &self.repo,
                sessions_dir: None,
                base_branch: &base,
                runtime: &runtime,
            }) {
                Ok(res) => json_resp(200, &res),
                Err(err) => json_resp(400, &json!({"error": err})),
            };
        }

        if path == "/api/sessions/approve" {
            let sid = get_str("session_id");
            let gate = get_str("gate");
            let actor = get_str("actor");
            let rationale = get_str("rationale");
            let digest = get_str("contract_digest");
            return match approve_gate(&ApproveGateArgs {
                session_id: &sid,
                gate: &gate,
                actor: &actor,
                rationale: &rationale,
                contract_digest: &digest,
                root: &self.root,
                repo: &self.repo,
                sessions_dir: None,
            }) {
                Ok(res) => json_resp(200, &res),
                Err(err) => json_resp(400, &json!({"error": err})),
            };
        }

        if path == "/api/sessions/advance" {
            let sid = get_str("session_id");
            let terminal = get_str("terminal_state");
            let receipt = payload.get("receipt").and_then(Value::as_object).cloned();
            return match advance_session(&AdvanceSessionArgs {
                session_id: &sid,
                receipt,
                terminal_state: &terminal,
                root: &self.root,
                repo: &self.repo,
                sessions_dir: None,
            }) {
                Ok(res) => json_resp(200, &res),
                Err(err) => json_resp(400, &json!({"error": err})),
            };
        }

        if path == "/api/solo-review" {
            let base = {
                let b = get_str("base");
                if b.is_empty() {
                    "origin/main".to_string()
                } else {
                    b
                }
            };
            let lighting = {
                let l = get_str("lighting");
                if l.is_empty() {
                    "auto".to_string()
                } else {
                    l
                }
            };
            return match run_solo_review(&SoloReviewArgs {
                base,
                root: self.root.clone(),
                repo: self.repo.clone(),
                contract_path: String::new(),
                builder_harness: get_str("builder"),
                manifest: String::new(),
                lighting,
                nc_command: get_str("nc_command"),
                no_gh: true,
                transcript_out: String::new(),
                transcript_key: String::new(),
                packet_out: String::new(),
            }) {
                Ok(res) => json_resp(200, &res),
                Err(err) => json_resp(400, &json!({"error": err})),
            };
        }

        if path == "/api/floor-check" {
            let base = {
                let b = get_str("base");
                if b.is_empty() {
                    "origin/main".to_string()
                } else {
                    b
                }
            };
            let tool_args = json!({
                "base": base,
                "repo": self.repo.to_string_lossy(),
            });
            return match self.mcp.call_tool("fleet_floor_check", Some(&tool_args)) {
                Ok(out) => json_resp(200, out.get("structuredContent").unwrap_or(&out)),
                Err(err) => json_resp(500, &json!({"error": err})),
            };
        }

        if path == "/api/readiness/cert-check" {
            let Ok(_guard) = self.demo_lock.try_lock() else {
                return json_resp(
                    429,
                    &json!({"error": "a verification task is already running"}),
                );
            };
            let rep = readiness_report(&self.root, &self.engine_version, true);
            return json_resp(200, rep.get("certification_check").unwrap_or(&rep));
        }

        if path == "/api/readiness/probes" {
            let Ok(_guard) = self.demo_lock.try_lock() else {
                return json_resp(
                    429,
                    &json!({"error": "a verification task is already running"}),
                );
            };
            return json_resp(200, &run_negative_probes(&self.root));
        }

        json_resp(404, &json!({"error": format!("not found: {path}")}))
    }
}

fn json_resp(status: u16, value: &Value) -> (u16, &'static str, Vec<u8>) {
    let mut body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    body.push(b'\n');
    (status, "application/json; charset=utf-8", body)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let mut query = HashMap::new();
    if let Some(q) = raw_query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k), percent_decode(v)),
                None => (percent_decode(pair), String::new()),
            };
            query.entry(k).or_insert(v);
        }
    }
    (raw_path.to_string(), query)
}

fn handle_connection(mut stream: TcpStream, app: Arc<MissionControlApp>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(reader_stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let target = parts[1];

    let mut content_length: Option<usize> = None;
    let mut bad_length = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                match v.trim().parse::<usize>() {
                    Ok(n) if n <= MAX_POST_BYTES => content_length = Some(n),
                    _ => bad_length = true,
                }
            }
        }
    }

    let (path, query) = parse_target(target);

    if method == "GET" && path == "/api/events/stream" {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let snap = json!({
            "ts": ts,
            "engine": "rust",
            "workspace": app.workspace_status()["runtime_state"]["summary"],
        });
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\nevent: snapshot\ndata: {}\n\n",
            snap
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        return;
    }

    let (status, ctype, payload) = match method {
        "GET" => app.handle_get(&path, &query),
        "POST" => {
            if bad_length {
                json_resp(400, &json!({"error": "invalid Content-Length"}))
            } else {
                let len = content_length.unwrap_or(0);
                let mut body = vec![0u8; len];
                if len > 0 && reader.read_exact(&mut body).is_err() {
                    json_resp(400, &json!({"error": "incomplete request body"}))
                } else {
                    app.handle_post(&path, &body)
                }
            }
        }
        _ => json_resp(
            405,
            &json!({"error": format!("method not allowed: {method}")}),
        ),
    };

    let header = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        payload.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&payload);
    let _ = stream.flush();
}

pub fn serve_ui(root: PathBuf, repo: PathBuf, host: &str, port: u16, engine_version: &str) -> i32 {
    let bind_addr = format!("{host}:{port}");
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("open-fleet ui: failed to bind {bind_addr}: {err}");
            return 2;
        }
    };
    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    println!("open-fleet Mission Control listening on http://{host}:{actual_port}");
    let _ = std::io::stdout().flush();

    let app = Arc::new(MissionControlApp::new(
        root,
        repo,
        engine_version.to_string(),
    ));

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        let app_ref = Arc::clone(&app);
        thread::spawn(move || handle_connection(stream, app_ref));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_decodes_query_and_path() {
        let (p, q) = parse_target("/api/route?q=review+PR+%2342&top=3");
        assert_eq!(p, "/api/route");
        assert_eq!(q.get("q").map(String::as_str), Some("review PR #42"));
        assert_eq!(q.get("top").map(String::as_str), Some("3"));
    }

    #[test]
    fn mission_control_app_serves_html_overview_and_route() {
        let cwd = std::env::current_dir().expect("cwd");
        let (root, _) = of_install::resolve_catalog_root(&cwd).expect("catalog");
        let app = MissionControlApp::new(root.clone(), root, "0.8.0".to_string());

        let (st, ct, html) = app.handle_get("/", &HashMap::new());
        assert_eq!(st, 200);
        assert!(ct.starts_with("text/html"));
        assert!(String::from_utf8_lossy(&html).contains("open-fleet Mission Control"));

        let (st_ov, _, ov_bytes) = app.handle_get("/api/overview", &HashMap::new());
        assert_eq!(st_ov, 200);
        let ov: Value = serde_json::from_slice(&ov_bytes).expect("overview json");
        assert!(ov["catalog"]["mission_count"].as_u64().unwrap_or(0) >= 22);
        assert!(ov["mcp_tools"].as_array().map(|a| a.len()).unwrap_or(0) >= 23);

        let (st_rt, _, rt_bytes) = app.handle_post("/api/route", br#"{"goal":"review PR #99"}"#);
        assert_eq!(st_rt, 200);
        let rt: Value = serde_json::from_slice(&rt_bytes).expect("route json");
        assert_eq!(rt["matches"][0]["mission"], "review-it");
    }
}
