//! Native Rust mission catalog discovery, metadata, certification summary,
//! and TF-IDF intent routing mirroring `open_fleet/catalog.py`.

pub mod frontmatter;

use frontmatter::{clause_refs, deferred_declared, parse_frontmatter, split_body, FmValue};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

pub fn mission_category(name: &str) -> &'static str {
    match name {
        "map-it" | "ship-it" | "oss-contribute" | "absorb-it" => "Plan, Build & Ship",
        "clean-sweep" | "deflake-it" | "field-test-it" => "Fix, Sweep & Stabilize",
        "review-it" | "root-cause" | "prove-it" | "floor-it" => "Review, Diagnose & Prove",
        "harden-it" | "attest-it" | "access-it" | "speed-it" => "Audit, Harden & Attest",
        "modernize-it" | "reshape-it" | "migrate-it" => "Evolve, Refactor & Migrate",
        "oncall-it" | "document-it" | "offload-it" | "pin-it" => "Operate, Document & Provision",
        _ => "Other",
    }
}

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for", "from", "get", "have",
    "how", "i", "if", "in", "into", "is", "it", "its", "me", "my", "need", "of", "on", "or", "our",
    "out", "please", "run", "should", "so", "that", "the", "their", "them", "there", "these",
    "this", "to", "up", "us", "use", "want", "we", "what", "when", "where", "which", "with",
    "would", "you", "your",
];

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9]+").expect("regex"))
}

fn not_for_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)\bNot\s+for\b.*").expect("regex"))
}

fn use_when_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)\bUse\s+when\b.*").expect("regex"))
}

fn md_link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\[([^\]]+)\]\(([^)]+)\)").expect("regex"))
}

fn read_json_value(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn catalog_version(root: &Path) -> String {
    if let Some(v) = read_json_value(&root.join(".claude-plugin/plugin.json")) {
        if let Some(s) = v.get("version").and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    fs::read_to_string(root.join("ENGINE_VERSION"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "0.0.0".to_string())
}

fn stem(word: &str) -> String {
    let w = word.to_lowercase();
    if w.len() <= 3 {
        return w;
    }
    for suffix in [
        "ation", "ition", "ment", "ness", "ings", "ing", "ied", "ies", "ed", "es", "ly", "er", "s",
    ] {
        if w.ends_with(suffix) && w.len() - suffix.len() >= 3 {
            let base = &w[..w.len() - suffix.len()];
            if suffix == "ies" || suffix == "ied" {
                return format!("{base}y");
            }
            return base.to_string();
        }
    }
    w
}

fn tokenize(text: &str, synonyms: &HashMap<String, Vec<String>>) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    for m in token_re().find_iter(&lower) {
        let tok = m.as_str();
        if STOPWORDS.contains(&tok) {
            continue;
        }
        out.push(stem(tok));
        if let Some(aliases) = synonyms.get(tok) {
            for alias in aliases {
                let al = alias.to_lowercase();
                for pm in token_re().find_iter(&al) {
                    let part = pm.as_str();
                    if !STOPWORDS.contains(&part) {
                        out.push(stem(part));
                    }
                }
            }
        }
    }
    out
}

fn split_description(desc: &str) -> (String, String, String) {
    let (before_not, not_for) = if let Some(m) = not_for_re().find(desc) {
        (&desc[..m.start()], m.as_str())
    } else {
        (desc, "")
    };
    let (main, use_when) = if let Some(m) = use_when_re().find(before_not) {
        (&before_not[..m.start()], m.as_str())
    } else {
        (before_not, "")
    };
    (
        main.trim().to_string(),
        use_when.trim().to_string(),
        not_for.trim().to_string(),
    )
}

fn extract_section(body: &str, heading: &str) -> String {
    let pat = format!(
        r"(?ms)^##\s+{}\b.*?\n(.*?)(?:^##\s+|\z)",
        regex::escape(heading)
    );
    let Ok(re) = Regex::new(&pat) else {
        return String::new();
    };
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

pub fn load_capabilities(root: &Path) -> Value {
    read_json_value(&root.join("runtime/providers/capabilities.json"))
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

pub fn load_certification(root: &Path) -> Value {
    read_json_value(&root.join("runtime/providers/certification.json"))
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

pub fn load_pins(root: &Path) -> Value {
    let Some(Value::Object(map)) = read_json_value(&root.join("runtime/pins.json")) else {
        return serde_json::json!({});
    };
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        if !k.starts_with('_') {
            out.insert(k, v);
        }
    }
    Value::Object(out)
}

pub fn load_quarantine(root: &Path) -> Value {
    let path = root.join("runtime/quarantine.json");
    if let Some(Value::Object(map)) = read_json_value(&path) {
        if let Some(Value::Array(arr)) = map.get("quarantined") {
            return serde_json::json!({
                "valid": true,
                "quarantined": arr,
                "error": Value::Null,
            });
        }
    }
    serde_json::json!({
        "valid": false,
        "quarantined": [],
        "error": format!("unreadable or malformed {}", path.display()),
    })
}

pub fn load_one_way_doors(root: &Path) -> Vec<Value> {
    read_json_value(&root.join("runtime/one-way-doors.json"))
        .and_then(|v| v.get("doors").and_then(|d| d.as_array()).cloned())
        .unwrap_or_default()
}

pub fn load_budgets(root: &Path) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    if let Some(v) = read_json_value(&root.join("scripts/mission-load-budgets.json")) {
        if let Some(Value::Object(b)) = v.get("budgets") {
            for (k, val) in b {
                if let Some(n) = val.as_i64() {
                    out.insert(k.clone(), n);
                } else if let Some(f) = val.as_f64() {
                    out.insert(k.clone(), f as i64);
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedRun {
    pub id: String,
    pub date: String,
    pub report: String,
    pub mission: String,
    pub mission_raw: String,
    pub target: String,
    pub ran_as: String,
    pub binds: String,
    pub binds_yes: bool,
    pub outcome: String,
}

pub fn load_retained_runs(root: &Path) -> Vec<RetainedRun> {
    let index_dir = root.join("docs/runs/index");
    let Ok(entries) = fs::read_dir(&index_dir) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths.reverse();

    let mut rows = Vec::new();
    for path in paths {
        let Some(Value::Object(row)) = read_json_value(&path) else {
            continue;
        };
        let get_s = |k: &str| -> String {
            row.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let mission_raw = get_s("mission");
        let mission_name = md_link_re()
            .captures(&mission_raw)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| mission_raw.clone());
        let binds = get_s("binds");
        let binds_yes = binds.trim().to_ascii_lowercase().starts_with("yes");
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        rows.push(RetainedRun {
            id,
            date: get_s("date"),
            report: get_s("report"),
            mission: mission_name,
            mission_raw,
            target: get_s("target"),
            ran_as: get_s("ran_as"),
            binds,
            binds_yes,
            outcome: get_s("outcome"),
        });
    }
    rows
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionIdentity {
    pub unit: String,
    pub state_machine: String,
    pub convergence: String,
    pub ordering: String,
    pub parking: String,
    pub oracle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionCapabilities {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mission {
    pub name: String,
    pub category: String,
    pub description: String,
    pub summary: String,
    pub use_when: String,
    pub not_for: String,
    pub compatibility: String,
    pub proof: String,
    pub proof_evidence: String,
    pub autonomy: String,
    pub activation_budget_tokens: i64,
    pub identity: MissionIdentity,
    pub capabilities: MissionCapabilities,
    pub composes: Vec<String>,
    pub deferred_reads: Vec<String>,
    pub guide_path: String,
    pub skill_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence_section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anti_patterns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_prompt: Option<String>,
}

pub fn build_launch_prompt(mission: &Mission, goal: &str) -> String {
    let name = &mission.name;
    let goal_text = if goal.trim().is_empty() {
        "<describe your bounded goal, target PR/issue, or spec path>"
    } else {
        goal.trim()
    };
    match name.as_str() {
        "review-it" => format!(
            "Run {name}: {goal_text}\nPin the exact head SHA, dispatch parallel read-only reviewers across acceptance axes plus triggered risk lenses, and return a quote-backed GO/NO-GO verdict without editing code."
        ),
        "ship-it" => format!(
            "Run {name}: {goal_text}\nPreflight against a dedicated integration BASE branch (never main), grill & freeze the spec at a human gate, dispatch isolated vertical slices with negative controls, and stop at the promotion PR."
        ),
        "clean-sweep" => format!(
            "Run {name}: {goal_text}\nFreeze the T0 finding denominator, open one PR per finding on an integration BASE branch backed by a pre-fix RED test and negative control, and re-enumerate until DRY."
        ),
        _ => format!(
            "Run {name}: {goal_text}\nFollow skills/{name}/SKILL.md: preflight first, honor one-way human gates, bind every unit to a SHA-verified evidence manifest, and stop at the authorized terminal state."
        ),
    }
}

pub fn list_missions(
    root: &Path,
    proof: Option<&str>,
    category: Option<&str>,
    include_body: bool,
) -> Vec<Mission> {
    let skills_dir = root.join("skills");
    let Ok(entries) = fs::read_dir(&skills_dir) else {
        return Vec::new();
    };
    let caps = load_capabilities(root);
    let caps_missions = caps.get("missions").and_then(|v| v.as_object());
    let budgets = load_budgets(root);

    let mut dirs: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| !s.starts_with('.') && !s.starts_with('_'))
                    .unwrap_or(false)
        })
        .collect();
    dirs.sort();

    let mut missions = Vec::new();
    for dir in dirs {
        let skill_md = dir.join("SKILL.md");
        if !skill_md.is_file() {
            continue;
        }
        let Ok(text) = fs::read_to_string(&skill_md) else {
            continue;
        };
        let Ok(fm) = parse_frontmatter(&text) else {
            continue;
        };
        let folder_name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let name = fm
            .get("name")
            .and_then(FmValue::as_str)
            .map(|s| s.to_string())
            .unwrap_or(folder_name);
        let meta = fm.get("metadata").and_then(FmValue::as_map);
        let meta_s = |k: &str| -> String {
            meta.and_then(|m| m.get(k))
                .and_then(FmValue::as_str)
                .unwrap_or("")
                .to_string()
        };
        let proof_tier = {
            let p = meta_s("proof");
            if p.is_empty() {
                "doctrine-only".to_string()
            } else {
                p
            }
        };
        let cat = mission_category(&name).to_string();
        if let Some(pf) = proof {
            if proof_tier != pf {
                continue;
            }
        }
        if let Some(cf) = category {
            if !cat.eq_ignore_ascii_case(cf) {
                continue;
            }
        }
        let desc = fm
            .get("description")
            .and_then(FmValue::as_str)
            .unwrap_or("")
            .to_string();
        let compat = fm
            .get("compatibility")
            .and_then(FmValue::as_str)
            .unwrap_or("")
            .to_string();
        let (summary, use_when, not_for) = split_description(&desc);
        let body_text = split_body(&text);
        let composes = clause_refs(&body_text);
        let deferred_reads = deferred_declared(&body_text);
        let cap_entry = caps_missions
            .and_then(|m| m.get(&name))
            .and_then(|v| v.as_object());
        let cap_list = |key: &str| -> Vec<String> {
            cap_entry
                .and_then(|e| e.get(key))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        let mut item = Mission {
            guide_path: format!("docs/missions/{name}.md"),
            skill_path: format!("skills/{name}/SKILL.md"),
            activation_budget_tokens: *budgets.get(&name).unwrap_or(&0),
            identity: MissionIdentity {
                unit: meta_s("unit"),
                state_machine: meta_s("state_machine"),
                convergence: meta_s("convergence"),
                ordering: meta_s("ordering"),
                parking: meta_s("parking"),
                oracle: meta_s("oracle"),
            },
            capabilities: MissionCapabilities {
                required: cap_list("required"),
                optional: cap_list("optional"),
            },
            name,
            category: cat,
            description: desc,
            summary,
            use_when,
            not_for,
            compatibility: compat,
            proof: proof_tier,
            proof_evidence: meta_s("proof_evidence"),
            autonomy: meta_s("autonomy"),
            composes,
            deferred_reads,
            body: None,
            convergence_section: None,
            anti_patterns: None,
            launch_prompt: None,
        };
        if include_body {
            item.convergence_section = Some(extract_section(&body_text, "Convergence proof"));
            item.anti_patterns = Some(extract_section(&body_text, "Anti-patterns"));
            item.launch_prompt = Some(build_launch_prompt(&item, ""));
            item.body = Some(body_text);
        }
        missions.push(item);
    }
    missions
}

pub fn get_mission(root: &Path, name: &str) -> Option<Mission> {
    list_missions(root, None, None, true)
        .into_iter()
        .find(|m| m.name == name)
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteMatch {
    pub mission: String,
    pub score: f64,
    pub evidence: f64,
    pub proof: String,
    pub category: String,
    pub summary: String,
    pub use_when: String,
    pub not_for: String,
    pub activation_budget_tokens: i64,
    pub required_capabilities: Vec<String>,
    pub matched_terms: Vec<String>,
    pub launch_prompt: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteResult {
    pub query: String,
    pub min_evidence: f64,
    pub above_floor: bool,
    pub recommended: Option<RouteMatch>,
    pub matches: Vec<RouteMatch>,
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

pub fn route_intent(root: &Path, prompt: &str, top_k: usize) -> RouteResult {
    let routing_cfg = read_json_value(&root.join("evals/routing.json"));
    let scoring = routing_cfg.as_ref().and_then(|v| v.get("scoring"));
    let name_w = scoring
        .and_then(|s| s.get("name_weight"))
        .and_then(|v| v.as_f64())
        .unwrap_or(2.0);
    let use_w = scoring
        .and_then(|s| s.get("use_when_weight"))
        .and_then(|v| v.as_f64())
        .unwrap_or(3.0);
    let excl_w = scoring
        .and_then(|s| s.get("exclusion_weight"))
        .and_then(|v| v.as_f64())
        .unwrap_or(-0.5);
    let min_evidence = scoring
        .and_then(|s| s.get("min_evidence"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.3);

    let mut synonyms: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(Value::Object(syn_map)) = routing_cfg.as_ref().and_then(|v| v.get("synonyms")) {
        for (k, v) in syn_map {
            if let Some(arr) = v.as_array() {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect();
                synonyms.insert(k.clone(), list);
            }
        }
    }

    let missions = list_missions(root, None, None, false);
    if prompt.trim().is_empty() || missions.is_empty() {
        return RouteResult {
            query: prompt.to_string(),
            min_evidence,
            above_floor: false,
            recommended: None,
            matches: Vec::new(),
        };
    }

    let query_tokens = tokenize(prompt, &synonyms);
    if query_tokens.is_empty() {
        return RouteResult {
            query: prompt.to_string(),
            min_evidence,
            above_floor: false,
            recommended: None,
            matches: Vec::new(),
        };
    }

    let mut doc_weights: Vec<HashMap<String, f64>> = Vec::with_capacity(missions.len());
    let mut df: HashMap<String, usize> = HashMap::new();

    for m in &missions {
        let mut weights: HashMap<String, f64> = HashMap::new();
        let mut seen_pos: HashSet<String> = HashSet::new();
        for tok in tokenize(&m.name.replace('-', " "), &synonyms) {
            *weights.entry(tok.clone()).or_insert(0.0) += name_w;
            seen_pos.insert(tok);
        }
        let main_text = format!("{} {}", m.summary, m.identity.unit);
        for tok in tokenize(&main_text, &synonyms) {
            *weights.entry(tok.clone()).or_insert(0.0) += 1.0;
            seen_pos.insert(tok);
        }
        for tok in tokenize(&m.use_when, &synonyms) {
            *weights.entry(tok.clone()).or_insert(0.0) += use_w;
            seen_pos.insert(tok);
        }
        for tok in tokenize(&m.not_for, &synonyms) {
            if !seen_pos.contains(&tok) {
                *weights.entry(tok).or_insert(0.0) += excl_w;
            }
        }
        for tok in seen_pos {
            *df.entry(tok).or_insert(0) += 1;
        }
        doc_weights.push(weights);
    }

    let n_docs = missions.len() as f64;
    let idf = |tok: &str| -> f64 {
        let d = *df.get(tok).unwrap_or(&0) as f64;
        ((n_docs + 1.0) / (d + 1.0)).ln() + 1.0
    };

    let mut q_counts: HashMap<String, f64> = HashMap::new();
    for tok in query_tokens {
        *q_counts.entry(tok).or_insert(0.0) += 1.0;
    }
    let q_vec: HashMap<String, f64> = q_counts
        .into_iter()
        .map(|(tok, tf)| {
            let w = tf * idf(&tok);
            (tok, w)
        })
        .collect();
    let q_norm_sq: f64 = q_vec.values().map(|v| v * v).sum();
    let q_norm = if q_norm_sq > 0.0 {
        q_norm_sq.sqrt()
    } else {
        1.0
    };

    let lower_prompt = prompt.to_lowercase();
    let mut ranked: Vec<RouteMatch> = Vec::with_capacity(missions.len());
    for (m, d_tf) in missions.iter().zip(doc_weights.iter()) {
        let mut d_vec: HashMap<&str, f64> = HashMap::with_capacity(d_tf.len());
        let mut d_norm_sq = 0.0;
        for (tok, w) in d_tf {
            let v = w * idf(tok);
            d_norm_sq += v * v;
            d_vec.insert(tok.as_str(), v);
        }
        let d_norm = if d_norm_sq > 0.0 {
            d_norm_sq.sqrt()
        } else {
            1.0
        };
        let mut dot = 0.0;
        let mut matched_terms: BTreeSet<String> = BTreeSet::new();
        for (tok, qv) in &q_vec {
            if let Some(dv) = d_vec.get(tok.as_str()) {
                dot += qv * dv;
            }
            if d_tf.get(tok).copied().unwrap_or(0.0) > 0.0 {
                matched_terms.insert(tok.clone());
            }
        }
        let mut evidence = dot / d_norm;
        let mut score = dot / (q_norm * d_norm);
        if lower_prompt.contains(&m.name) {
            score += 0.55;
            if evidence < min_evidence + 0.5 {
                evidence = min_evidence + 0.5;
            }
        }
        ranked.push(RouteMatch {
            mission: m.name.clone(),
            score: round4(score),
            evidence: round4(evidence),
            proof: m.proof.clone(),
            category: m.category.clone(),
            summary: m.summary.clone(),
            use_when: m.use_when.clone(),
            not_for: m.not_for.clone(),
            activation_budget_tokens: m.activation_budget_tokens,
            required_capabilities: m.capabilities.required.clone(),
            matched_terms: matched_terms.into_iter().collect(),
            launch_prompt: build_launch_prompt(m, prompt),
        });
    }

    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.mission.cmp(&b.mission))
    });
    let limit = top_k.max(1).min(ranked.len());
    let top: Vec<RouteMatch> = ranked.into_iter().take(limit).collect();
    let best = top.first().cloned();
    let above_floor = best
        .as_ref()
        .map(|b| b.evidence >= min_evidence)
        .unwrap_or(false);
    RouteResult {
        query: prompt.to_string(),
        min_evidence,
        above_floor,
        recommended: if above_floor { best } else { None },
        matches: top,
    }
}

pub fn certification_summary(root: &Path) -> Value {
    let cert = load_certification(root);
    let caps = load_capabilities(root);
    let cert_providers = cert.get("providers").and_then(|v| v.as_object());
    let cap_providers = caps.get("providers").and_then(|v| v.as_object());

    let mut providers_out = Vec::new();
    if let Some(cp_map) = cap_providers {
        let mut names: Vec<&String> = cp_map.keys().collect();
        names.sort();
        for pname in names {
            let p_cap = &cp_map[pname];
            let p_cert = cert_providers.and_then(|m| m.get(pname));
            let mut counts: BTreeMap<&str, usize> = BTreeMap::from([
                ("live-witnessed", 0),
                ("fixture-tested", 0),
                ("source-only", 0),
                ("unsupported", 0),
                ("unavailable", 0),
            ]);
            let mut live_cells = Vec::new();
            if let Some(routes) = p_cert
                .and_then(|c| c.get("routes"))
                .and_then(|r| r.as_array())
            {
                for group in routes {
                    let tier = group
                        .get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unavailable");
                    let profiles = group
                        .get("profiles")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let harnesses = group
                        .get("harnesses")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let n_cells = profiles.len() * harnesses.len();
                    if let Some(c) = counts.get_mut(tier) {
                        *c += n_cells;
                    }
                    if tier == "live-witnessed" {
                        live_cells.push(serde_json::json!({
                            "profiles": profiles,
                            "harnesses": harnesses,
                            "witnessed": group.get("witnessed").cloned().unwrap_or_else(|| serde_json::json!({})),
                            "evidence": group.get("evidence").cloned().unwrap_or_else(|| serde_json::json!([])),
                        }));
                    }
                }
            }
            let cert_ver = p_cert
                .and_then(|c| c.get("upstream"))
                .and_then(|u| u.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            providers_out.push(serde_json::json!({
                "name": pname,
                "tier": p_cap.get("tier").cloned().unwrap_or(Value::Null),
                "upstream": p_cap.get("upstream").cloned().unwrap_or(Value::Null),
                "certified_version": cert_ver,
                "description": p_cap.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                "supported_profiles": p_cap.get("supported_profiles").cloned().unwrap_or_else(|| serde_json::json!([])),
                "supported_harnesses": p_cap.get("supported_harnesses").cloned().unwrap_or_else(|| serde_json::json!([])),
                "native_capabilities": p_cap.get("native_capabilities").cloned().unwrap_or_else(|| serde_json::json!([])),
                "fallback_capabilities": p_cap.get("fallback_capabilities").cloned().unwrap_or_else(|| serde_json::json!([])),
                "cell_counts": counts,
                "live_cells": live_cells,
            }));
        }
    }

    let mut harnesses_out = Vec::new();
    if let Some(ch_map) = cert.get("harnesses").and_then(|v| v.as_object()) {
        let mut names: Vec<&String> = ch_map.keys().collect();
        names.sort();
        for hname in names {
            let h_cert = &ch_map[hname];
            let mut counts: BTreeMap<&str, usize> = BTreeMap::from([
                ("live-witnessed", 0),
                ("fixture-tested", 0),
                ("source-only", 0),
                ("unsupported", 0),
                ("unavailable", 0),
            ]);
            if let Some(routes) = h_cert.get("routes").and_then(|r| r.as_array()) {
                for group in routes {
                    let tier = group
                        .get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unavailable");
                    let n = group
                        .get("profiles")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if let Some(c) = counts.get_mut(tier) {
                        *c += n;
                    }
                }
            }
            let ver = h_cert
                .get("upstream")
                .and_then(|u| u.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            harnesses_out.push(serde_json::json!({
                "name": hname,
                "version": ver,
                "cell_counts": counts,
            }));
        }
    }

    serde_json::json!({
        "record_version": cert.get("record_version").cloned().unwrap_or(Value::Null),
        "recorded": cert.get("recorded").cloned().unwrap_or(Value::Null),
        "providers": providers_out,
        "harnesses": harnesses_out,
        "capabilities": caps.get("capabilities").cloned().unwrap_or_else(|| serde_json::json!({})),
    })
}

pub fn catalog_overview(root: &Path) -> Value {
    let missions = list_missions(root, None, None, false);
    let mut external_run = 0usize;
    let mut self_run = 0usize;
    let mut doctrine_only = 0usize;
    for m in &missions {
        match m.proof.as_str() {
            "external-run" => external_run += 1,
            "self-run" => self_run += 1,
            "doctrine-only" => doctrine_only += 1,
            _ => {}
        }
    }
    let runs = load_retained_runs(root);
    let binding_runs = runs.iter().filter(|r| r.binds_yes).count();
    let cert = certification_summary(root);
    let mut live_cells = 0u64;
    if let Some(arr) = cert.get("providers").and_then(|v| v.as_array()) {
        for p in arr {
            live_cells += p
                .get("cell_counts")
                .and_then(|c| c.get("live-witnessed"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
        }
    }
    if let Some(arr) = cert.get("harnesses").and_then(|v| v.as_array()) {
        for h in arr {
            live_cells += h
                .get("cell_counts")
                .and_then(|c| c.get("live-witnessed"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
        }
    }
    let provider_count = cert
        .get("providers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let harness_count = cert
        .get("harnesses")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    serde_json::json!({
        "version": catalog_version(root),
        "root": root.display().to_string(),
        "mission_count": missions.len(),
        "proof_counts": {
            "external-run": external_run,
            "self-run": self_run,
            "doctrine-only": doctrine_only,
        },
        "provider_count": provider_count,
        "harness_count": harness_count,
        "live_witnessed_cells": live_cells,
        "retained_runs_total": runs.len(),
        "retained_runs_binding": binding_runs,
        "quarantine": load_quarantine(root),
        "pins": load_pins(root),
        "one_way_door_count": load_one_way_doors(root).len(),
    })
}
