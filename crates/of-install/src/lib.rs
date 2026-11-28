//! Native multi-harness setup, skill installer, atomic Claude hook merger, embedded
//! standalone catalog materialization, and fast `doctor` diagnostics for `open-fleet`.

pub mod embedded;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct HarnessProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub skills_rel: &'static str,
    pub settings_rel: Option<&'static str>,
    pub mcp_rel: &'static str,
    pub supports_hooks: bool,
    pub invocation: &'static str,
}

pub const HARNESS_PROFILES: &[HarnessProfile] = &[
    HarnessProfile {
        id: "claude",
        label: "Claude Code",
        skills_rel: ".claude/skills",
        settings_rel: Some(".claude/settings.json"),
        mcp_rel: ".claude.json",
        supports_hooks: true,
        invocation: "/review-it or natural language",
    },
    HarnessProfile {
        id: "cursor",
        label: "Cursor",
        skills_rel: ".cursor/skills",
        settings_rel: None,
        mcp_rel: ".cursor/mcp.json",
        supports_hooks: false,
        invocation: "MCP tools + skills",
    },
    HarnessProfile {
        id: "codex",
        label: "OpenAI Codex CLI",
        skills_rel: ".codex/skills",
        settings_rel: None,
        mcp_rel: ".codex/config.toml",
        supports_hooks: false,
        invocation: "$review-it or natural language",
    },
    HarnessProfile {
        id: "gemini",
        label: "Gemini CLI",
        skills_rel: ".gemini/skills",
        settings_rel: Some(".gemini/settings.json"),
        mcp_rel: ".gemini/settings.json",
        supports_hooks: false,
        invocation: "natural language (invoke map-it by name)",
    },
    HarnessProfile {
        id: "opencode",
        label: "OpenCode",
        skills_rel: ".config/opencode/skills",
        settings_rel: None,
        mcp_rel: ".config/opencode/opencode.json",
        supports_hooks: false,
        invocation: "/review-it or natural language",
    },
    HarnessProfile {
        id: "antigravity",
        label: "Antigravity (agy)",
        skills_rel: ".gemini/antigravity-cli/skills",
        settings_rel: None,
        mcp_rel: ".gemini/antigravity-cli/mcp_config.json",
        supports_hooks: false,
        invocation: "/review-it or natural language",
    },
];

const DETECTED_BINS: &[(&str, &str)] = &[
    ("claude", "claude"),
    ("cursor", "cursor"),
    ("codex", "codex"),
    ("gemini", "gemini"),
    ("opencode", "opencode"),
    ("copilot", "gh"),
    ("antigravity", "agy"),
    ("windsurf", "windsurf"),
    ("hermes", "hermes"),
    ("omp", "omp"),
    ("pi", "pi"),
    ("grok", "grok"),
    ("droid", "droid"),
];

pub fn which(binary: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    for dir in env::split_paths(&path_var) {
        for ext in exts {
            let cand = dir.join(format!("{binary}{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogSource {
    Checkout,
    Embedded,
}

impl CatalogSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CatalogSource::Checkout => "checkout",
            CatalogSource::Embedded => "embedded",
        }
    }
}

fn is_catalog_dir(dir: &Path) -> bool {
    if !dir.join("skills").is_dir() || !dir.join("runtime").is_dir() {
        return false;
    }
    dir.join("runtime/providers/capabilities.json").is_file()
        || dir.join("runtime/quarantine.json").is_file()
        || !discover_missions(dir).is_empty()
}

pub fn find_catalog_root(start: &Path) -> Option<PathBuf> {
    if let Ok(explicit) = env::var("OPEN_FLEET_ROOT") {
        let p = PathBuf::from(explicit);
        if is_catalog_dir(&p) {
            return Some(p);
        }
    }
    let abs = fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let mut cur = Some(abs.as_path());
    while let Some(dir) = cur {
        if is_catalog_dir(dir) {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    if let Ok(exe) = env::current_exe() {
        let mut cur_exe = exe.parent();
        while let Some(dir) = cur_exe {
            if is_catalog_dir(dir) {
                return Some(dir.to_path_buf());
            }
            cur_exe = dir.parent();
        }
    }
    None
}

/// Resolve the open-fleet catalog root, preferring an explicit/checkout directory
/// (`OPEN_FLEET_ROOT` or enclosing repo) and falling back to materializing the
/// compile-time embedded catalog under `~/.open-fleet/catalog/<version>-<sha12>/`.
pub fn resolve_catalog_root(start: &Path) -> Result<(PathBuf, CatalogSource), String> {
    if let Some(root) = find_catalog_root(start) {
        return Ok((root, CatalogSource::Checkout));
    }
    let materialized = embedded::materialize_catalog(None, env!("CARGO_PKG_VERSION"))?;
    Ok((materialized, CatalogSource::Embedded))
}

pub fn discover_missions(catalog_root: &Path) -> Vec<String> {
    let skills_dir = catalog_root.join("skills");
    let Ok(rd) = fs::read_dir(&skills_dir) else {
        return Vec::new();
    };
    let mut missions = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir()
            && !name.starts_with('.')
            && !name.starts_with('_')
            && path.join("SKILL.md").is_file()
        {
            missions.push(name);
        }
    }
    missions.sort();
    missions
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub engine: &'static str,
    pub engine_version: String,
    pub binary_path: String,
    pub binary_sha256: Option<String>,
    pub git_available: bool,
    pub git_path: Option<String>,
    pub catalog_root: Option<String>,
    pub catalog_source: String,
    pub embedded_catalog_files: usize,
    pub embedded_catalog_sha256: String,
    pub missions_count: usize,
    pub runtime_configured: String,
    pub detected_harnesses: BTreeMap<String, String>,
    pub claude_floor_hook_wired: bool,
    pub claude_deny_hook_wired: bool,
    pub ready: bool,
}

fn file_sha256(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(hex::encode(hasher.finalize()))
}

fn check_claude_floor_hook(home: &Path) -> bool {
    let settings = home.join(".claude/settings.json");
    let Ok(text) = fs::read_to_string(&settings) else {
        return false;
    };
    let Ok(val) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    let Some(hooks) = val.get("hooks").and_then(|v| v.as_object()) else {
        return false;
    };
    for event in ["Stop", "TaskCompleted"] {
        let Some(entries) = hooks.get(event).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in entries {
            let Some(inner) = entry.get("hooks").and_then(|v| v.as_array()) else {
                continue;
            };
            for h in inner {
                if let Some(cmd) = h.get("command").and_then(|v| v.as_str()) {
                    if cmd.contains("open-fleet") && cmd.contains("floor") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_deny_hook_command(cmd: &str) -> bool {
    cmd.contains("deny-hook.sh")
        || (cmd.contains("open-fleet")
            && (cmd.contains("deny-hook")
                || (cmd.contains("hook") && cmd.contains("--mode") && cmd.contains("deny"))))
}

fn check_claude_deny_hook(home: &Path) -> bool {
    let settings = home.join(".claude/settings.json");
    let Ok(text) = fs::read_to_string(&settings) else {
        return false;
    };
    let Ok(val) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    let Some(hooks) = val.get("hooks").and_then(|v| v.as_object()) else {
        return false;
    };
    let Some(entries) = hooks.get("PreToolUse").and_then(|v| v.as_array()) else {
        return false;
    };
    for entry in entries {
        let Some(inner) = entry.get("hooks").and_then(|v| v.as_array()) else {
            continue;
        };
        for h in inner {
            if let Some(cmd) = h.get("command").and_then(|v| v.as_str()) {
                if is_deny_hook_command(cmd) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn doctor(repo: &Path, engine_version: &str) -> DoctorReport {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("open-fleet"));
    let exe_sha = file_sha256(&exe);
    let git_path = of_common::gitexec::git_binary()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let resolved = resolve_catalog_root(repo).ok();
    let (catalog, catalog_source) = match resolved {
        Some((p, src)) => (Some(p), src.as_str().to_string()),
        None => (None, "missing".to_string()),
    };
    let missions_count = catalog
        .as_deref()
        .map(|c| discover_missions(c).len())
        .unwrap_or(0);
    let runtime_configured = env::var("OPEN_FLEET_RUNTIME")
        .or_else(|_| env::var("ORCA_FLEET_RUNTIME"))
        .unwrap_or_else(|_| "auto".to_string());

    let mut detected_harnesses = BTreeMap::new();
    for (name, bin) in DETECTED_BINS {
        if let Some(p) = which(bin) {
            detected_harnesses.insert((*name).to_string(), p.to_string_lossy().into_owned());
        }
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let claude_floor_hook_wired = check_claude_floor_hook(&home);
    let claude_deny_hook_wired = check_claude_deny_hook(&home);
    let ready = git_path.is_some() && missions_count > 0;

    DoctorReport {
        engine: "rust",
        engine_version: engine_version.to_string(),
        binary_path: exe.to_string_lossy().into_owned(),
        binary_sha256: exe_sha,
        git_available: git_path.is_some(),
        git_path,
        catalog_root: catalog.map(|p| p.to_string_lossy().into_owned()),
        catalog_source,
        embedded_catalog_files: embedded::embedded_file_count(),
        embedded_catalog_sha256: embedded::EMBEDDED_CATALOG_SHA256.to_string(),
        missions_count,
        runtime_configured,
        detected_harnesses,
        claude_floor_hook_wired,
        claude_deny_hook_wired,
        ready,
    }
}

#[derive(Debug, Clone)]
pub struct InstallConfig {
    pub harness: String,
    pub scope: String,
    pub mode: String,
    pub home: PathBuf,
    pub repo: PathBuf,
    pub with_hooks: bool,
    pub dry_run: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessInstallResult {
    pub harness: String,
    pub label: String,
    pub skills_dir: String,
    pub missions_installed: usize,
    pub hook_wired: bool,
    pub deny_hook_wired: bool,
    pub settings_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub ok: bool,
    pub dry_run: bool,
    pub mode: String,
    pub scope: String,
    pub catalog_root: String,
    pub catalog_source: String,
    pub targets: Vec<HarnessInstallResult>,
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("readdir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("readdir entry: {e}"))?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if s.is_dir() {
            copy_dir_recursive(&s, &d)?;
        } else if s.is_file() {
            fs::copy(&s, &d)
                .map_err(|e| format!("copy {} -> {}: {e}", s.display(), d.display()))?;
        }
    }
    Ok(())
}

fn install_skill(src: &Path, dst: &Path, mode: &str) -> Result<(), String> {
    if dst.exists() || fs::symlink_metadata(dst).is_ok() {
        let meta = fs::symlink_metadata(dst).map_err(|e| format!("stat {}: {e}", dst.display()))?;
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(dst).map_err(|e| format!("remove {}: {e}", dst.display()))?;
        } else {
            fs::remove_dir_all(dst).map_err(|e| format!("rmdir {}: {e}", dst.display()))?;
        }
    }
    if mode == "symlink" {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(src, dst)
                .map_err(|e| format!("symlink {} -> {}: {e}", src.display(), dst.display()))?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            return copy_dir_recursive(src, dst);
        }
    }
    copy_dir_recursive(src, dst)
}

pub fn merge_claude_floor_hooks(
    settings_path: &Path,
    bin_cmd: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let mut root: Value = if settings_path.is_file() {
        let text = fs::read_to_string(settings_path)
            .map_err(|e| format!("read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("{} is not valid JSON: {e}", settings_path.display()))?
    } else {
        json!({})
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| format!("{} must be a JSON object", settings_path.display()))?;
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| "settings.json `hooks` must be a JSON object".to_string())?;

    let floor_cmd = format!("{bin_cmd} floor --quiet");
    let deny_cmd = format!("{bin_cmd} hook --mode deny");
    let mut changed = false;

    for event in ["Stop", "TaskCompleted"] {
        let entries = hooks
            .entry(event)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| format!("settings.json `hooks.{event}` must be an array"))?;

        let already = entries.iter().any(|entry| {
            entry
                .get("hooks")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|h| {
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(|c| c.contains("open-fleet") && c.contains("floor"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        if !already {
            entries.push(json!({
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": floor_cmd,
                        "timeout": 30
                    }
                ]
            }));
            changed = true;
        }
    }

    {
        let pre_entries = hooks
            .entry("PreToolUse")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| "settings.json `hooks.PreToolUse` must be an array".to_string())?;
        let already_deny = pre_entries.iter().any(|entry| {
            entry
                .get("hooks")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|h| {
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(is_deny_hook_command)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        if !already_deny {
            pre_entries.push(json!({
                "matcher": "Bash|Edit|Write|NotebookEdit|MultiEdit",
                "hooks": [
                    {
                        "type": "command",
                        "command": deny_cmd,
                        "timeout": 30
                    }
                ]
            }));
            changed = true;
        }
    }

    if !dry_run && (changed || !settings_path.is_file()) {
        if let Some(parent) = settings_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let tmp = settings_path.with_extension("json.tmp");
        let serialized = serde_json::to_string_pretty(&root)
            .map_err(|e| format!("serialize settings.json: {e}"))?;
        fs::write(&tmp, format!("{serialized}\n"))
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, settings_path).map_err(|e| {
            format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                settings_path.display()
            )
        })?;
    }
    Ok(true)
}

pub fn install(cfg: &InstallConfig) -> Result<InstallReport, String> {
    if !matches!(cfg.mode.as_str(), "symlink" | "copy") {
        return Err(format!(
            "--mode must be 'symlink' or 'copy', got {:?}",
            cfg.mode
        ));
    }
    if !matches!(cfg.scope.as_str(), "user" | "project") {
        return Err(format!(
            "--scope must be 'user' or 'project', got {:?}",
            cfg.scope
        ));
    }
    let (catalog_root, catalog_source) = resolve_catalog_root(&cfg.repo)?;
    let missions = discover_missions(&catalog_root);
    if missions.is_empty() {
        return Err(format!(
            "no missions found under {}/skills",
            catalog_root.display()
        ));
    }

    let selected: Vec<&HarnessProfile> = if cfg.harness.trim() == "all" {
        HARNESS_PROFILES.iter().collect()
    } else {
        let mut out: Vec<&HarnessProfile> = Vec::new();
        for raw in cfg.harness.split(',') {
            let name = raw.trim();
            if name.is_empty() {
                continue;
            }
            if name == "all" {
                out = HARNESS_PROFILES.iter().collect();
                break;
            }
            let p = HARNESS_PROFILES
                .iter()
                .find(|h| h.id == name)
                .ok_or_else(|| {
                    let valid: Vec<&str> = HARNESS_PROFILES.iter().map(|h| h.id).collect();
                    format!(
                        "unknown harness {:?}; expected one of: {}, all",
                        name,
                        valid.join(", ")
                    )
                })?;
            if !out.iter().any(|existing| existing.id == p.id) {
                out.push(p);
            }
        }
        if out.is_empty() {
            let valid: Vec<&str> = HARNESS_PROFILES.iter().map(|h| h.id).collect();
            return Err(format!(
                "unknown harness {:?}; expected one of: {}, all",
                cfg.harness,
                valid.join(", ")
            ));
        }
        out
    };

    let base_dir = if cfg.scope == "project" {
        &cfg.repo
    } else {
        &cfg.home
    };

    let exe_cmd = env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| format!("\"{s}\"")))
        .unwrap_or_else(|| "open-fleet".to_string());

    let mut targets = Vec::new();
    for profile in selected {
        let skills_dir = base_dir.join(profile.skills_rel);
        if !cfg.dry_run {
            fs::create_dir_all(&skills_dir)
                .map_err(|e| format!("mkdir {}: {e}", skills_dir.display()))?;
            for m in &missions {
                let src = catalog_root.join("skills").join(m);
                let dst = skills_dir.join(m);
                install_skill(&src, &dst, &cfg.mode)?;
            }
        }
        let mut hook_wired = false;
        let mut settings_out = None;
        if cfg.with_hooks && profile.supports_hooks {
            if let Some(rel) = profile.settings_rel {
                let sp = base_dir.join(rel);
                hook_wired = merge_claude_floor_hooks(&sp, &exe_cmd, cfg.dry_run)?;
                settings_out = Some(sp.to_string_lossy().into_owned());
            }
        }
        targets.push(HarnessInstallResult {
            harness: profile.id.to_string(),
            label: profile.label.to_string(),
            skills_dir: skills_dir.to_string_lossy().into_owned(),
            missions_installed: missions.len(),
            hook_wired,
            deny_hook_wired: hook_wired,
            settings_path: settings_out,
        });
    }

    Ok(InstallReport {
        ok: true,
        dry_run: cfg.dry_run,
        mode: cfg.mode.clone(),
        scope: cfg.scope.clone(),
        catalog_root: catalog_root.to_string_lossy().into_owned(),
        catalog_source: catalog_source.as_str().to_string(),
        targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_claude_hooks_is_idempotent_and_preserves_existing() {
        let tmp = std::env::temp_dir().join(format!("of-install-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("mkdir");
        let sp = tmp.join("settings.json");
        fs::write(
            &sp,
            r#"{"theme":"dark","hooks":{"Stop":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .expect("write");

        merge_claude_floor_hooks(&sp, "open-fleet", false).expect("first merge");
        merge_claude_floor_hooks(&sp, "open-fleet", false).expect("second merge");

        let parsed: Value =
            serde_json::from_str(&fs::read_to_string(&sp).expect("read")).expect("json");
        assert_eq!(parsed["theme"], "dark");
        assert_eq!(parsed["hooks"]["Stop"].as_array().expect("arr").len(), 2);
        assert_eq!(
            parsed["hooks"]["TaskCompleted"]
                .as_array()
                .expect("arr")
                .len(),
            1
        );
        assert_eq!(
            parsed["hooks"]["PreToolUse"].as_array().expect("arr").len(),
            1
        );
        let pre_cmd = parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .expect("pre command");
        assert!(is_deny_hook_command(pre_cmd));
        let _ = fs::remove_dir_all(&tmp);
    }
}
