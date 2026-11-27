//! Native Rust port of `runtime/scripts/quarantine_check.py`:
//! the fleet-wide component off-switch (#558).

use chrono::NaiveDate;
use of_catalog::frontmatter::{
    clause_refs, deferred_declared, is_valid_name, parse_frontmatter, protocol_closure,
};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const KINDS: &[&str] = &["mission", "playbook", "pack"];

pub const RESERVED_HUMAN_NAMES: &[&str] = &[
    "agent",
    "ai",
    "anonymous",
    "auto",
    "automatic",
    "bot",
    "coordinator",
    "fleet",
    "human",
    "model",
    "nobody",
    "none",
    "orca",
    "system",
    "unknown",
    "worker",
];

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{7,40}$").expect("regex"))
}

fn human_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9._-]*$").expect("regex"))
}

fn by_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^human:(\S+)$").expect("regex"))
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineEntry {
    pub kind: String,
    pub name: String,
    pub r#ref: String,
    pub reason: String,
    pub by: String,
}

#[derive(Debug, Clone, Default)]
pub struct CatalogView {
    pub missions: BTreeSet<String>,
    pub composes: BTreeMap<String, BTreeSet<String>>,
    pub pins: BTreeMap<String, String>,
    pub pins_error: Option<String>,
}

fn val_as_py_str(v: Option<&Value>, default: &str) -> String {
    match v {
        None | Some(Value::Null) => default.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn valid_ymd(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    if parts[0].len() != 4
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        parts[0].parse::<i32>(),
        parts[1].parse::<u32>(),
        parts[2].parse::<u32>(),
    ) else {
        return false;
    };
    NaiveDate::from_ymd_opt(y, m, d).is_some()
}

pub fn parse_quarantine(data: &Value) -> (Vec<QuarantineEntry>, Vec<String>) {
    let mut errors = Vec::new();
    let Some(obj) = data.as_object() else {
        return (
            Vec::new(),
            vec!["quarantine.json: expected an object with a 'quarantined' list".to_string()],
        );
    };
    let Some(list) = obj.get("quarantined").and_then(|v| v.as_array()) else {
        return (
            Vec::new(),
            vec!["quarantine.json: expected an object with a 'quarantined' list".to_string()],
        );
    };
    let mut entries = Vec::new();
    for (i, raw) in list.iter().enumerate() {
        let where_s = format!("quarantine.json entry {i}");
        let Some(map) = raw.as_object() else {
            errors.push(format!("{where_s}: not an object"));
            continue;
        };
        let comp_val = map.get("component");
        let (kind, name) = match comp_val.and_then(|v| v.as_str()) {
            Some(c) => match c.split_once(':') {
                Some((k, n)) => (k, n),
                None => (c, ""),
            },
            None => ("", ""),
        };
        if !KINDS.contains(&kind) || name.is_empty() || name.contains(':') {
            errors.push(format!(
                "{where_s}: component must be '<kind>:<name>' with kind in {} (got {:?})",
                KINDS.join("/"),
                val_as_py_str(comp_val, "")
            ));
            continue;
        }
        let ref_val = map.get("ref");
        let ref_s = match ref_val {
            None => "*".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        if ref_s != "*" && !hex_re().is_match(&ref_s) {
            errors.push(format!(
                "{where_s}: ref must be '*' or at least 7 hex chars (got {ref_s:?})"
            ));
            continue;
        }
        let reason_s = val_as_py_str(map.get("reason"), "");
        if reason_s.trim().is_empty() {
            errors.push(format!(
                "{where_s}: reason is required — a quarantine with no reason is a rumor"
            ));
            continue;
        }
        let date_s = val_as_py_str(map.get("date"), "");
        if !valid_ymd(&date_s) {
            errors.push(format!(
                "{where_s}: date must be YYYY-MM-DD (got {date_s:?})"
            ));
            continue;
        }
        let by_s = val_as_py_str(map.get("by"), "");
        let by_name = by_re()
            .captures(&by_s)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        if !human_name_re().is_match(by_name)
            || RESERVED_HUMAN_NAMES.contains(&by_name.to_ascii_lowercase().as_str())
        {
            errors.push(format!(
                "{where_s}: by must be 'human:<name>' naming a person — entries are human acts, never agent-added"
            ));
            continue;
        }
        entries.push(QuarantineEntry {
            kind: kind.to_string(),
            name: name.to_string(),
            r#ref: ref_s,
            reason: reason_s,
            by: by_s,
        });
    }
    (entries, errors)
}

pub fn load_quarantine(root: &Path) -> (Vec<QuarantineEntry>, Vec<String>, bool) {
    let path = root.join("runtime/quarantine.json");
    if fs::symlink_metadata(&path).is_err() {
        return (Vec::new(), Vec::new(), false);
    }
    if !path.is_file() {
        return (
            Vec::new(),
            vec![format!(
                "{}: present but not a regular file — refusing to treat an unusable deny-list as an absent one",
                path.display()
            )],
            true,
        );
    }
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(err) => {
            return (
                Vec::new(),
                vec![format!("{}: cannot parse ({err})", path.display())],
                true,
            )
        }
    };
    let data: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(err) => {
            return (
                Vec::new(),
                vec![format!("{}: cannot parse ({err})", path.display())],
                true,
            )
        }
    };
    let (entries, errors) = parse_quarantine(&data);
    (entries, errors, true)
}

pub fn ref_matches(ref_s: &str, commit: &str) -> bool {
    if ref_s == "*" {
        return true;
    }
    if commit.is_empty() {
        return false;
    }
    let rl = ref_s.to_ascii_lowercase();
    let cl = commit.to_ascii_lowercase();
    cl.starts_with(&rl) || rl.starts_with(&cl)
}

pub fn violations(entries: &[QuarantineEntry], view: &CatalogView) -> Vec<String> {
    let mut out = Vec::new();
    for e in entries {
        let label = format!(
            "{}:{} (quarantined by {}: {})",
            e.kind, e.name, e.by, e.reason
        );
        match e.kind.as_str() {
            "mission" => {
                if view.missions.contains(&e.name) {
                    out.push(format!("mission {} is quarantined — {label}", e.name));
                }
            }
            "playbook" => {
                for (mission, playbooks) in &view.composes {
                    if playbooks.contains(&e.name) {
                        out.push(format!(
                            "mission {mission} composes quarantined playbook {} — {label}",
                            e.name
                        ));
                    }
                }
            }
            "pack" => {
                if let Some(perr) = &view.pins_error {
                    out.push(format!(
                        "pack {} cannot be cleared — {perr} — refusing rather than assuming the quarantined pack is unused",
                        e.name
                    ));
                    continue;
                }
                if let Some(commit) = view.pins.get(&e.name) {
                    if ref_matches(&e.r#ref, commit) {
                        out.push(format!(
                            "pack {} is pinned at quarantined ref {commit} — {label}",
                            e.name
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn read_dependency(doc: &Path) -> Result<String, String> {
    fs::read_to_string(doc)
        .map_err(|err| format!("{}: unreadable composed dependency ({err})", doc.display()))
}

fn composed_playbooks(
    skill_text: &str,
    root: &Path,
    skill_dir: &Path,
) -> Result<BTreeSet<String>, String> {
    let references = skill_dir.join("references");
    let bundled = references.is_dir() || skill_dir == root;
    let bases: Vec<PathBuf> = if bundled {
        vec![references]
    } else {
        vec![root.join("playbooks"), root.join("runtime")]
    };
    let mut listings: HashMap<PathBuf, BTreeSet<String>> = HashMap::new();

    let mut resolve_in = |name: &str| -> Option<PathBuf> {
        let target_file = format!("{name}.md");
        for base in &bases {
            let set = listings.entry(base.clone()).or_insert_with(|| {
                let mut names = BTreeSet::new();
                if let Ok(rd) = fs::read_dir(base) {
                    for entry in rd.flatten() {
                        if let Ok(n) = entry.file_name().into_string() {
                            names.insert(n);
                        }
                    }
                }
                names
            });
            if set.contains(&target_file) {
                return Some(base.join(&target_file));
            }
        }
        None
    };

    let mut declared: BTreeSet<String> = clause_refs(skill_text).into_iter().collect();
    for d in deferred_declared(skill_text) {
        declared.insert(d);
    }
    for name in declared {
        let Some(doc) = resolve_in(&name) else {
            let tried: Vec<String> = bases
                .iter()
                .map(|b| b.join(format!("{name}.md")).display().to_string())
                .collect();
            return Err(format!(
                "missing composed dependency {name}.md (tried {}) — cannot clear the mission against the deny-list",
                tried.join(", ")
            ));
        };
        read_dependency(&doc)?;
    }

    let reached = protocol_closure(skill_text, resolve_in, |p| read_dependency(p))?;
    let runtime_dir = root.join("runtime");
    Ok(reached
        .into_iter()
        .filter(|(_, doc)| bundled || doc.parent() != Some(runtime_dir.as_path()))
        .map(|(name, _)| name)
        .collect())
}

pub fn pins_view(root: &Path) -> (BTreeMap<String, String>, Option<String>) {
    let path = root.join("runtime/pins.json");
    if fs::symlink_metadata(&path).is_err() {
        return (BTreeMap::new(), None);
    }
    if !path.is_file() {
        return (
            BTreeMap::new(),
            Some(format!(
                "{}: present but not a regular file",
                path.display()
            )),
        );
    }
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(err) => {
            return (
                BTreeMap::new(),
                Some(format!("{}: cannot parse ({err})", path.display())),
            )
        }
    };
    let data: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(err) => {
            return (
                BTreeMap::new(),
                Some(format!("{}: cannot parse ({err})", path.display())),
            )
        }
    };
    let Some(obj) = data.as_object() else {
        return (
            BTreeMap::new(),
            Some(format!("{}: expected a JSON object", path.display())),
        );
    };
    let mut pins = BTreeMap::new();
    for (name, meta) in obj {
        if name.starts_with('_') {
            continue;
        }
        if let Some(m) = meta.as_object() {
            let commit = val_as_py_str(m.get("commit"), "");
            pins.insert(name.clone(), commit);
        }
    }
    (pins, None)
}

pub fn mission_view(root: &Path, mission: &str) -> Result<CatalogView, String> {
    if !is_valid_name(mission) {
        return Err(format!(
            "invalid mission name {mission:?} — must match ^[a-z0-9]+(-[a-z0-9]+)*$"
        ));
    }
    let candidates = [
        root.join("skills").join(mission).join("SKILL.md"),
        root.join("SKILL.md"),
    ];
    let Some(skill) = candidates.into_iter().find(|c| c.is_file()) else {
        return Err(format!(
            "no SKILL.md for {mission} under {} (tried skills/{mission}/SKILL.md and ./SKILL.md) — cannot tell what it composes, so cannot clear it against the deny-list",
            root.display()
        ));
    };
    let text = fs::read_to_string(&skill)
        .map_err(|err| format!("{}: unreadable ({err})", skill.display()))?;
    let mut missions = BTreeSet::new();
    missions.insert(mission.to_string());
    match parse_frontmatter(&text) {
        Ok(fm) => {
            let declared = fm.get("name").and_then(|v| v.as_str());
            let Some(decl) = declared else {
                return Err(format!(
                    "{}: frontmatter 'name' is missing or invalid (None)",
                    skill.display()
                ));
            };
            if !is_valid_name(decl) {
                return Err(format!(
                    "{}: frontmatter 'name' is missing or invalid ({decl:?})",
                    skill.display()
                ));
            }
            if decl != mission {
                return Err(format!(
                    "{}: frontmatter name {decl:?} does not match requested mission {mission:?} — refusing to clear an aliased or mismatched mission",
                    skill.display()
                ));
            }
            missions.clear();
            missions.insert(decl.to_string());
        }
        Err(ref err) if err == "missing opening ---" => {}
        Err(err) => {
            return Err(format!(
                "{}: malformed frontmatter ({err}) — cannot verify mission identity",
                skill.display()
            ));
        }
    }
    let skill_dir = skill.parent().unwrap_or(root);
    let comp = composed_playbooks(&text, root, skill_dir)?;
    let mut composes = BTreeMap::new();
    composes.insert(mission.to_string(), comp);
    let (pins, pins_error) = pins_view(root);
    Ok(CatalogView {
        missions,
        composes,
        pins,
        pins_error,
    })
}

pub fn catalog_view(root: &Path) -> Result<CatalogView, String> {
    let skills = root.join("skills");
    let mut missions = BTreeSet::new();
    let mut composes = BTreeMap::new();
    if skills.is_dir() {
        let mut dirs: Vec<PathBuf> = fs::read_dir(&skills)
            .map_err(|e| format!("{}: unreadable ({e})", skills.display()))?
            .flatten()
            .map(|e| e.path())
            .collect();
        dirs.sort();
        for skill_dir in dirs {
            let skill = skill_dir.join("SKILL.md");
            if skill_dir.is_dir() && skill.exists() {
                if let Some(name) = skill_dir.file_name().and_then(|n| n.to_str()) {
                    missions.insert(name.to_string());
                    let mv = mission_view(root, name)?;
                    if let Some(c) = mv.composes.get(name) {
                        composes.insert(name.to_string(), c.clone());
                    }
                }
            }
        }
    }
    let (pins, pins_error) = pins_view(root);
    Ok(CatalogView {
        missions,
        composes,
        pins,
        pins_error,
    })
}

pub struct QuarantineArgs {
    pub root: PathBuf,
    pub catalog: bool,
    pub mission: Option<String>,
}

pub fn run_cli(args: &QuarantineArgs) -> i32 {
    if !args.root.is_dir() {
        eprintln!(
            "quarantine_check: root {} is not a directory",
            args.root.display()
        );
        return 3;
    }
    let (entries, errors, present) = load_quarantine(&args.root);
    if !errors.is_empty() {
        for err in &errors {
            eprintln!("quarantine_check: {err}");
        }
        return 3;
    }
    if !present {
        eprintln!(
            "quarantine_check: no runtime/quarantine.json under {} — no quarantine in force (not a fleet catalog?)",
            args.root.display()
        );
        return 0;
    }
    let mut view = if args.catalog {
        match catalog_view(&args.root) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("quarantine_check: {err}");
                return 3;
            }
        }
    } else if let Some(mission) = &args.mission {
        match mission_view(&args.root, mission) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("quarantine_check: {err}");
                return 3;
            }
        }
    } else {
        eprintln!("quarantine_check: expected --catalog or --mission");
        return 2;
    };

    if args.catalog {
        let mut present_missions: Vec<&str> = entries
            .iter()
            .filter(|e| e.kind == "mission" && view.missions.contains(&e.name))
            .map(|e| e.name.as_str())
            .collect();
        present_missions.sort();
        for name in present_missions {
            println!(
                "QUARANTINED mission {name} present in the catalog (dispatch refused at preflight; files preserved as evidence)"
            );
        }
        view.missions.clear();
    }

    let found = violations(&entries, &view);
    for v in &found {
        println!("QUARANTINED {v}");
    }
    if !found.is_empty() {
        return 2;
    }
    println!("quarantine_check: clean");
    0
}
