//! Native Rust port of `runtime/scripts/preflight.py`:
//! hard fail-closed preflight invariants for autonomous fleet runs (#558, #586, M-5).

use crate::quarantine::{load_quarantine, mission_view, violations};
use of_common::gitexec::{custody_env, git_binary};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const GIT_TIMEOUT_SECS: u64 = 10;
const GH_TIMEOUT_SECS: u64 = 30;

const KNOWN_PROVIDERS: &[&str] = &[
    "orca",
    "posix",
    "local-posix",
    "superset",
    "gastown",
    "worktrunk",
    "openhands",
    "overstory",
    "t3code",
    "ao",
    "jcode-swarm",
    "emdash",
    "vibe-kanban",
    "paperclip",
    "multiclaude",
];

fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn realpath_best(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        }
    })
}

fn fleet_root_env() -> Result<Option<String>, String> {
    let new_v = env::var("OPEN_FLEET_ROOT").ok().filter(|s| !s.is_empty());
    let old_v = env::var("ORCA_FLEET_ROOT").ok().filter(|s| !s.is_empty());
    if let (Some(ref n), Some(ref l)) = (&new_v, &old_v) {
        if realpath_best(&expand_tilde(n)) != realpath_best(&expand_tilde(l)) {
            return Err(format!(
                "OPEN_FLEET_ROOT ({n}) and the legacy ORCA_FLEET_ROOT ({l}) are both set and disagree — refusing (fail-closed: one spelling must not silently override the other; set one)"
            ));
        }
    }
    Ok(new_v.or(old_v))
}

fn exe_catalog_root() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let mut cur = exe.parent();
    while let Some(d) = cur {
        if d.join("skills").is_dir() && d.join("runtime").is_dir() {
            return Some(d.to_path_buf());
        }
        cur = d.parent();
    }
    None
}

fn catalog_roots(explicit_root: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    if let Some(r) = explicit_root {
        roots.push(r.to_path_buf());
    }
    if let Some(fr) = fleet_root_env()? {
        roots.push(PathBuf::from(fr));
    }
    if let Ok(cp) = env::var("CLAUDE_PLUGIN_ROOT") {
        if !cp.is_empty() {
            roots.push(PathBuf::from(cp));
        }
    }
    if let Some(er) = exe_catalog_root() {
        roots.push(er);
    }
    Ok(roots)
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let p = Path::new(name);
    if p.components().count() > 1 {
        return if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_var = env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    for dir in env::split_paths(&path_var) {
        for ext in exts {
            let cand = dir.join(format!("{name}{ext}"));
            if cand.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = fs::metadata(&cand) {
                        if (meta.permissions().mode() & 0o111) != 0 {
                            return Some(cand);
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    return Some(cand);
                }
            }
        }
    }
    None
}

fn is_invisible_char(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || (0x7F..=0x9F).contains(&u)
        || matches!(u, 0x2028 | 0x2029)
        || of_common::decisions::has_invisible_cf(&c.to_string())
}

fn cli_command_problem(value: &str, var: &str) -> Option<String> {
    let rule = "it must name one executable, without arguments";
    let why = if value.chars().any(is_invisible_char) {
        "holds a control, format or separator character"
    } else if value.starts_with('-') {
        "is option-shaped"
    } else if !Path::new(value).is_absolute() && value.chars().any(|c| c.is_whitespace()) {
        "is a command line, not one executable"
    } else if !Path::new(value).is_absolute() && value.contains('/') {
        "is a relative path"
    } else {
        return None;
    };
    Some(format!("{var}={value:?} {why} ({rule})"))
}

fn resolve_orca_binary() -> Result<String, String> {
    for var in ["OPEN_FLEET_CLI_COMMAND", "ORCA_CLI_COMMAND"] {
        if let Ok(raw) = env::var(var) {
            let trimmed = raw.trim_matches([' ', '\t', '\r', '\n', '\x0b', '\x0c']);
            if !trimmed.is_empty() {
                if let Some(prob) = cli_command_problem(trimmed, var) {
                    return Err(prob);
                }
                return Ok(trimmed.to_string());
            }
        }
    }
    if let Ok(dev) = env::var("ORCA_DEV_REPO_ROOT") {
        if !dev.trim().is_empty() {
            return Ok("orca-dev".to_string());
        }
    }
    if cfg!(target_os = "linux") {
        Ok("orca-ide".to_string())
    } else {
        Ok("orca".to_string())
    }
}

fn resolve_provider(runtime: &str) -> Result<String, (bool, String)> {
    let raw = runtime.trim().to_ascii_lowercase();
    if raw.is_empty() || raw == "orca" {
        return Ok("orca".to_string());
    }
    if raw == "local-posix" {
        return Ok("posix".to_string());
    }
    if raw == "auto" {
        let orca_bin = resolve_orca_binary().map_err(|e| (false, e))?;
        return if which_on_path(&orca_bin).is_some() {
            Ok("orca".to_string())
        } else {
            Ok("posix".to_string())
        };
    }
    if !KNOWN_PROVIDERS.contains(&raw.as_str()) {
        return Err((true, format!("unknown runtime provider {raw:?}")));
    }
    Ok(raw)
}

fn fallback_probe(provider: &str, cap: &str) -> Option<&'static [&'static str]> {
    if provider == "posix" && cap == "cap:sandbox-vm" {
        return Some(&["docker"]);
    }
    if cap == "cap:sandbox-vm" {
        return Some(&[]);
    }
    if cap == "cap:mobile-emulator" {
        return Some(&["adb", "xcrun"]);
    }
    None
}

fn active_runtime(explicit: Option<&str>) -> Option<String> {
    if let Some(r) = explicit {
        let t = r.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    for var in ["OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME"] {
        if let Ok(v) = env::var(var) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn capabilities_refusal(
    mission: Option<&str>,
    runtime: &str,
    strict_native: bool,
    roots: &[PathBuf],
) -> (Option<String>, Map<String, Value>) {
    let found_root = roots
        .iter()
        .find(|r| fs::symlink_metadata(r.join("runtime/providers/capabilities.json")).is_ok());
    let Some(root) = found_root else {
        let msg = "runtime/providers/capabilities.json is missing — refusing rather than assuming capabilities".to_string();
        let mut info = Map::new();
        info.insert("ok".to_string(), json!(false));
        info.insert("error".to_string(), json!(msg));
        return (Some(msg), info);
    };
    let cap_path = root.join("runtime/providers/capabilities.json");
    let data: Value = match fs::read_to_string(&cap_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(err) => {
            let msg = format!("runtime/providers/capabilities.json is malformed ({err})");
            let mut info = Map::new();
            info.insert("ok".to_string(), json!(false));
            info.insert("error".to_string(), json!(msg));
            return (Some(msg), info);
        }
    };
    let Some(obj) = data.as_object() else {
        let msg = "runtime/providers/capabilities.json must be a JSON object".to_string();
        let mut info = Map::new();
        info.insert("ok".to_string(), json!(false));
        info.insert("error".to_string(), json!(msg));
        return (Some(msg), info);
    };
    let (Some(providers), Some(missions)) = (
        obj.get("providers").and_then(|v| v.as_object()),
        obj.get("missions").and_then(|v| v.as_object()),
    ) else {
        let msg = "runtime/providers/capabilities.json is missing 'providers' or 'missions' map"
            .to_string();
        let mut info = Map::new();
        info.insert("ok".to_string(), json!(false));
        info.insert("error".to_string(), json!(msg));
        return (Some(msg), info);
    };

    let mut known_vec: Vec<&str> = providers.keys().map(|s| s.as_str()).collect();
    known_vec.sort();
    let known = known_vec.join(", ");

    let provider_name = match resolve_provider(runtime) {
        Ok(p) => p,
        Err((is_unknown, err_msg)) => {
            let msg = if is_unknown {
                format!(
                    "unknown_runtime: '{runtime}' is not a registered RPI provider (known: {known})"
                )
            } else {
                format!(
                    "runtime provider registry unloadable ({err_msg}) — refusing rather than guessing"
                )
            };
            let mut info = Map::new();
            info.insert("ok".to_string(), json!(false));
            info.insert("runtime".to_string(), json!(runtime));
            info.insert("error".to_string(), json!(msg));
            return (Some(msg), info);
        }
    };

    let Some(p_entry) = providers.get(&provider_name) else {
        let msg = format!(
            "unknown_runtime: '{runtime}' is not a registered RPI provider (known: {known})"
        );
        let mut info = Map::new();
        info.insert("ok".to_string(), json!(false));
        info.insert("runtime".to_string(), json!(runtime));
        info.insert("error".to_string(), json!(msg));
        return (Some(msg), info);
    };
    let Some(p_obj) = p_entry.as_object() else {
        let msg =
            format!("runtime/providers/capabilities.json provider '{provider_name}' is malformed");
        let mut info = Map::new();
        info.insert("ok".to_string(), json!(false));
        info.insert("runtime".to_string(), json!(provider_name));
        info.insert("error".to_string(), json!(msg));
        return (Some(msg), info);
    };

    let native: BTreeSet<String> = p_obj
        .get("native_capabilities")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let fallback: BTreeSet<String> = p_obj
        .get("fallback_capabilities")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .filter(|c| !native.contains(c))
        .collect();
    let declared: BTreeSet<String> = if strict_native {
        native.clone()
    } else {
        native.union(&fallback).cloned().collect()
    };

    let mut info = Map::new();
    info.insert(
        "mission".to_string(),
        mission.map(|s| json!(s)).unwrap_or(Value::Null),
    );
    info.insert("runtime".to_string(), json!(provider_name));
    info.insert("requested_runtime".to_string(), json!(runtime));
    info.insert("strict_native".to_string(), json!(strict_native));
    info.insert(
        "native_capabilities".to_string(),
        json!(native.iter().collect::<Vec<_>>()),
    );
    info.insert(
        "fallback_capabilities".to_string(),
        if strict_native {
            json!([])
        } else {
            json!(fallback.iter().collect::<Vec<_>>())
        },
    );

    if let Some(mname) = mission {
        let Some(m_obj) = missions.get(mname).and_then(|v| v.as_object()) else {
            let msg = format!(
                "unknown_mission: '{mname}' is not declared in runtime/providers/capabilities.json"
            );
            info.insert("ok".to_string(), json!(false));
            info.insert("error".to_string(), json!(msg));
            return (Some(msg), info);
        };
        let required: Vec<String> = m_obj
            .get("required")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let optional: Vec<String> = m_obj
            .get("optional")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let mut missing: Vec<String> = required
            .iter()
            .filter(|c| !declared.contains(*c))
            .cloned()
            .collect();
        let mut probes: BTreeMap<String, Value> = BTreeMap::new();
        let mut unprobed: Vec<String> = Vec::new();
        for cap in &required {
            if native.contains(cap) || !declared.contains(cap) {
                continue;
            }
            let Some(tools) = fallback_probe(&provider_name, cap) else {
                unprobed.push(cap.clone());
                continue;
            };
            let found = tools
                .iter()
                .copied()
                .find(|t| which_on_path(t).is_some())
                .map(|s| s.to_string());
            probes.insert(
                cap.clone(),
                json!({
                    "ok": found.is_some(),
                    "tools": tools,
                    "found": found,
                }),
            );
            if found.is_none() {
                missing.push(cap.clone());
            }
        }
        let mut fallbacks_used: Vec<String> = required
            .iter()
            .filter(|c| !native.contains(*c) && !missing.contains(*c))
            .cloned()
            .collect();
        fallbacks_used.sort();
        let mut opt_unavail: Vec<String> = optional
            .iter()
            .filter(|c| !declared.contains(*c))
            .cloned()
            .collect();
        opt_unavail.sort();

        info.insert("required".to_string(), json!(required));
        info.insert("fallbacks_used".to_string(), json!(fallbacks_used));
        info.insert("fallback_probes".to_string(), json!(probes));
        info.insert("unprobed_fallbacks".to_string(), json!(unprobed));
        info.insert("optional_unavailable".to_string(), json!(opt_unavail));

        if !missing.is_empty() {
            let first = missing[0].clone();
            let mode_note = if strict_native {
                " (strict-native)"
            } else {
                ""
            };
            let mut parts = Vec::new();
            for c in &missing {
                let hint = if let Some(probe) = probes.get(c) {
                    let tools: Vec<&str> = probe
                        .get("tools")
                        .and_then(|v| v.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.as_str())
                        .collect();
                    if tools.is_empty() {
                        format!(" (no probed fallback launch path for runtime '{provider_name}')")
                    } else {
                        format!(
                            " (fallback tooling absent: none of {} on PATH)",
                            tools.join(", ")
                        )
                    }
                } else {
                    String::new()
                };
                parts.push(format!("missing_capability: {c}{hint}"));
            }
            let msg = format!(
                "mission '{mname}' cannot run on runtime '{provider_name}'{mode_note} — {}",
                parts.join(", ")
            );
            info.insert("ok".to_string(), json!(false));
            info.insert("missing_capability".to_string(), json!(first));
            info.insert("missing_capabilities".to_string(), json!(missing));
            info.insert("error".to_string(), json!(msg));
            return (Some(msg), info);
        }
    }

    info.insert("ok".to_string(), json!(true));
    info.insert(
        "capabilities".to_string(),
        json!(declared.iter().collect::<Vec<_>>()),
    );
    (None, info)
}

fn quarantine_refusal(mission: Option<&str>, roots: &[PathBuf]) -> Option<String> {
    let root = roots
        .iter()
        .find(|r| fs::symlink_metadata(r.join("runtime/quarantine.json")).is_ok())?;
    let (entries, errors, _) = load_quarantine(root);
    if !errors.is_empty() {
        return Some(format!(
            "runtime/quarantine.json is malformed: {}",
            errors.join("; ")
        ));
    }
    let Some(mname) = mission else {
        if !entries.is_empty() {
            return Some(
                "--mission is required while runtime/quarantine.json has active entries — cannot clear an unidentified mission against the deny-list".to_string(),
            );
        }
        return None;
    };
    let view = match mission_view(root, mname) {
        Ok(v) => v,
        Err(err) => return Some(err),
    };
    let found = violations(&entries, &view);
    if !found.is_empty() {
        return Some(found.join("; "));
    }
    None
}

fn run_cmd_timeout(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout_secs: u64,
    is_git: bool,
) -> (Option<i32>, String, String) {
    let mut cmd = if is_git {
        let Ok(gb) = git_binary() else {
            return (Some(127), String::new(), "git is not on PATH".to_string());
        };
        let mut c = Command::new(gb);
        c.env_clear().envs(custody_env(&[]));
        c
    } else {
        Command::new(program)
    };
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => return (Some(127), String::new(), err.to_string()),
    };

    let stdout_handle = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();

    match status {
        None => {
            let mut all = vec![program];
            all.extend_from_slice(args);
            (
                None,
                String::new(),
                format!("`{}` timed out after {timeout_secs}s", all.join(" ")),
            )
        }
        Some(st) => (Some(st.code().unwrap_or(1)), stdout, stderr),
    }
}

fn default_branch_via_gh(cwd: &Path) -> Option<String> {
    let (rc, out, _) = run_cmd_timeout(
        "gh",
        &[
            "repo",
            "view",
            "--json",
            "defaultBranchRef",
            "-q",
            ".defaultBranchRef.name",
        ],
        cwd,
        GH_TIMEOUT_SECS,
        false,
    );
    if rc == Some(0) && !out.is_empty() {
        Some(format!("refs/remotes/origin/{out}"))
    } else {
        None
    }
}

fn branch_exists(name: &str, cwd: &Path) -> bool {
    if name.starts_with("refs/") {
        let (rc, _, _) = run_cmd_timeout(
            "git",
            &["show-ref", "--verify", "--quiet", name],
            cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        return rc == Some(0)
            && (name.starts_with("refs/heads/") || name.starts_with("refs/remotes/"));
    }
    for full in [
        format!("refs/heads/{name}"),
        format!("refs/remotes/origin/{name}"),
    ] {
        let (rc, _, _) = run_cmd_timeout(
            "git",
            &["show-ref", "--verify", "--quiet", &full],
            cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        if rc == Some(0) {
            return true;
        }
    }
    false
}

fn ref_candidates(rref: &str, cwd: &Path) -> Vec<String> {
    if rref.starts_with("refs/") {
        let (rc, out, _) = run_cmd_timeout(
            "git",
            &["show-ref", "--verify", "--hash", rref],
            cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        if rc == Some(0) && !out.is_empty() {
            return vec![out];
        }
        return Vec::new();
    }
    vec![rref.to_string(), format!("origin/{rref}")]
}

fn merge_base(a: &str, b: &str, cwd: &Path) -> Option<String> {
    let a_refs = ref_candidates(a, cwd);
    let b_refs = ref_candidates(b, cwd);
    for (i, j) in [(0, 0), (1, 1), (0, 1), (1, 0)] {
        if i >= a_refs.len() || j >= b_refs.len() {
            continue;
        }
        let (rc, out, _) = run_cmd_timeout(
            "git",
            &["merge-base", &a_refs[i], &b_refs[j]],
            cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        if rc == Some(0) && !out.is_empty() {
            return Some(out);
        }
    }
    None
}

fn canon_branch(rref: &str, cwd: &Path) -> String {
    let (rc, full, _) = run_cmd_timeout(
        "git",
        &["rev-parse", "--symbolic-full-name", rref],
        cwd,
        GIT_TIMEOUT_SECS,
        true,
    );
    if rc == Some(0) && !full.is_empty() {
        if let Some(rest) = full.strip_prefix("refs/remotes/") {
            return rest
                .split_once('/')
                .map(|(_, b)| b.to_string())
                .unwrap_or_else(|| rest.to_string());
        }
        if let Some(rest) = full.strip_prefix("refs/heads/") {
            return rest.to_string();
        }
        return full;
    }
    let mut name = rref;
    for prefix in ["refs/remotes/", "refs/heads/"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            name = rest;
        }
    }
    if let Some(rest) = name.strip_prefix("origin/") {
        name = rest;
    }
    name.to_string()
}

fn tip_sha(rref: &str, cwd: &Path) -> Option<String> {
    for cand in ref_candidates(rref, cwd) {
        let (rc, out, _) = run_cmd_timeout(
            "git",
            &["rev-parse", "--verify", "--quiet", &cand],
            cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        if rc == Some(0) && !out.is_empty() {
            return Some(out);
        }
    }
    None
}

fn print_fallback_notes(cap_info: Option<&Map<String, Value>>) {
    let Some(info) = cap_info else { return };
    let runtime = info.get("runtime").and_then(|v| v.as_str()).unwrap_or("");
    let used: Vec<&str> = info
        .get("fallbacks_used")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    if !used.is_empty() {
        let probes = info.get("fallback_probes").and_then(|v| v.as_object());
        let shown: Vec<String> = used
            .iter()
            .map(|c| {
                if let Some(found) = probes
                    .and_then(|p| p.get(*c))
                    .and_then(|o| o.get("found"))
                    .and_then(|f| f.as_str())
                {
                    format!("{c} via {found}")
                } else {
                    format!("{c} (unprobed)")
                }
            })
            .collect();
        eprintln!(
            "preflight: NOTE: runtime {runtime} satisfies {} by fallback, not natively",
            shown.join(", ")
        );
    }
    let opt: Vec<&str> = info
        .get("optional_unavailable")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    if !opt.is_empty() {
        eprintln!(
            "preflight: NOTE: optional capabilities unavailable on {runtime}: {}",
            opt.join(", ")
        );
    }
}

#[derive(Debug, Clone)]
pub struct PreflightArgs {
    pub base: Option<String>,
    pub default_branch: Option<String>,
    pub fork_point: Option<String>,
    pub mode: String,
    pub require_gitleaks: bool,
    pub offline: bool,
    pub mission: Option<String>,
    pub runtime: Option<String>,
    pub strict_native: bool,
    pub json: bool,
    pub cwd: Option<PathBuf>,
    pub catalog_root: Option<PathBuf>,
}

impl Default for PreflightArgs {
    fn default() -> Self {
        Self {
            base: None,
            default_branch: None,
            fork_point: None,
            mode: "write".to_string(),
            require_gitleaks: false,
            offline: false,
            mission: None,
            runtime: None,
            strict_native: false,
            json: false,
            cwd: None,
            catalog_root: None,
        }
    }
}

/// Custom parser matching `preflight.py`'s `_UsageExit1Parser`:
/// unknown flags, bad `--mode` choices, or missing flag values exit `1` (usage),
/// NEVER `2` (which is strictly reserved for invariant violations).
pub fn parse_raw_args(raw: &[OsString]) -> Result<Option<PreflightArgs>, String> {
    let mut out = PreflightArgs::default();
    let mut i = 0;
    while i < raw.len() {
        let arg = raw[i].to_string_lossy();
        if arg == "--" {
            i += 1;
            continue;
        }
        if arg == "-h" || arg == "--help" {
            println!("usage: open-fleet preflight [--base BRANCH] [--default BRANCH] [--fork-point SHA] [--mode write|readonly] [--require-gitleaks] [--offline] [--mission NAME] [--runtime PROVIDER] [--strict-native-capabilities] [--json]");
            return Ok(None);
        }
        let (flag, inline_val) = match arg.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (arg.to_string(), None),
        };
        let mut take_val = |name: &str| -> Result<String, String> {
            if let Some(v) = inline_val.clone() {
                return Ok(v);
            }
            if i + 1 >= raw.len() {
                return Err(format!("argument {name}: expected one argument"));
            }
            i += 1;
            Ok(raw[i].to_string_lossy().into_owned())
        };
        match flag.as_str() {
            "--base" => out.base = Some(take_val("--base")?),
            "--default" => out.default_branch = Some(take_val("--default")?),
            "--fork-point" => out.fork_point = Some(take_val("--fork-point")?),
            "--mode" => {
                let m = take_val("--mode")?;
                if m != "write" && m != "readonly" {
                    return Err(format!(
                        "argument --mode: invalid choice: '{m}' (choose from 'write', 'readonly')"
                    ));
                }
                out.mode = m;
            }
            "--require-gitleaks" => out.require_gitleaks = true,
            "--offline" => out.offline = true,
            "--mission" => out.mission = Some(take_val("--mission")?),
            "--runtime" => out.runtime = Some(take_val("--runtime")?),
            "--strict-native-capabilities" | "--strict-native" => out.strict_native = true,
            "--json" => out.json = true,
            "--repo" => out.cwd = Some(PathBuf::from(take_val("--repo")?)),
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }
    Ok(Some(out))
}

pub fn evaluate(args: &PreflightArgs) -> (i32, Value, String, String) {
    let cwd = args
        .cwd
        .clone()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let mut cap_info: Option<Map<String, Value>> = None;
    let effective_mode = args.mode.as_str();

    let make_fail = |msg: String,
                     code: i32,
                     ci: Option<&Map<String, Value>>,
                     extra: Option<(&str, Value)>|
     -> (i32, Value, String, String) {
        let mut payload = ci.cloned().unwrap_or_default();
        payload.insert("ok".to_string(), json!(false));
        payload.insert("exit".to_string(), json!(code));
        payload.insert("mode".to_string(), json!(effective_mode));
        payload.insert("error".to_string(), json!(msg));
        if let Some((k, v)) = extra {
            payload.insert(k.to_string(), v);
        }
        let val = Value::Object(payload);
        let stdout = if args.json {
            serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
        } else {
            String::new()
        };
        (code, val, stdout, format!("preflight: ERROR: {msg}"))
    };

    let roots = match catalog_roots(args.catalog_root.as_deref()) {
        Ok(r) => r,
        Err(err) => return make_fail(err, 2, None, None),
    };

    let mut runtime_provider = active_runtime(args.runtime.as_deref());
    if runtime_provider.is_none() && args.mission.is_some() {
        runtime_provider = Some("orca".to_string());
    }
    if let Some(ref rt) = runtime_provider {
        let (refusal, info) =
            capabilities_refusal(args.mission.as_deref(), rt, args.strict_native, &roots);
        if let Some(msg) = refusal {
            let val = Value::Object(info);
            let stdout = if args.json {
                serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
            } else {
                String::new()
            };
            return (2, val, stdout, format!("preflight: ERROR: {msg}"));
        }
        cap_info = Some(info);
    }

    if effective_mode == "write" && args.base.as_deref().unwrap_or("").is_empty() {
        return make_fail(
            "--base is required unless --mode readonly".to_string(),
            1,
            cap_info.as_ref(),
            None,
        );
    }
    if args.offline && args.default_branch.as_deref().unwrap_or("").is_empty() {
        return make_fail(
            "--default is required with --offline (no gh to derive it)".to_string(),
            1,
            cap_info.as_ref(),
            None,
        );
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let required: &[&str] = if effective_mode == "readonly" || args.offline {
        &["git"]
    } else {
        &["git", "gh"]
    };
    for bin in required {
        if which_on_path(bin).is_none() {
            errors.push(format!("missing required binary on PATH: {bin}"));
        }
    }
    if effective_mode == "write" {
        if args.require_gitleaks && which_on_path("gitleaks").is_none() {
            errors.push(
                "missing required binary on PATH: gitleaks (--require-gitleaks was set)"
                    .to_string(),
            );
        } else if which_on_path("gitleaks").is_none() {
            warnings.push(
                "gitleaks not on PATH — integrator secret scan step will be skipped".to_string(),
            );
        }
    }
    if !errors.is_empty() {
        let mut payload = cap_info.clone().unwrap_or_default();
        payload.insert("ok".to_string(), json!(false));
        payload.insert("exit".to_string(), json!(1));
        payload.insert("mode".to_string(), json!(effective_mode));
        payload.insert("error".to_string(), json!(errors.join("; ")));
        payload.insert("errors".to_string(), json!(errors));
        let val = Value::Object(payload);
        let stdout = if args.json {
            serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
        } else {
            String::new()
        };
        let stderr = errors
            .iter()
            .map(|e| format!("preflight: ERROR: {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        return (1, val, stdout, stderr);
    }

    let (rc, _, _) = run_cmd_timeout(
        "git",
        &["rev-parse", "--git-dir"],
        &cwd,
        GIT_TIMEOUT_SECS,
        true,
    );
    if rc != Some(0) {
        return make_fail(
            "not inside a git repository".to_string(),
            1,
            cap_info.as_ref(),
            None,
        );
    }

    if let Some(refusal) = quarantine_refusal(args.mission.as_deref(), &roots) {
        return make_fail(
            format!("QUARANTINED {refusal}"),
            2,
            cap_info.as_ref(),
            Some(("quarantined", json!(true))),
        );
    }

    if effective_mode == "readonly" {
        let mut payload = cap_info.clone().unwrap_or_default();
        payload.insert("ok".to_string(), json!(true));
        payload.insert("mode".to_string(), json!("readonly"));
        let val = Value::Object(payload);
        let stdout = if args.json {
            serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
        } else {
            let rt_suffix = cap_info
                .as_ref()
                .and_then(|c| c.get("runtime"))
                .and_then(|v| v.as_str())
                .map(|r| format!(", runtime={r}"))
                .unwrap_or_default();
            format!(
                "preflight: OK — mode=readonly{rt_suffix} (binary + repo checks only; no BASE/PR invariants)"
            )
        };
        if !args.json {
            print_fallback_notes(cap_info.as_ref());
        }
        return (0, val, stdout, String::new());
    }

    let repo_str = if args.offline {
        "(offline — gh skipped)".to_string()
    } else {
        let (rc, out, gh_err) = run_cmd_timeout(
            "gh",
            &[
                "repo",
                "view",
                "--json",
                "nameWithOwner",
                "-q",
                ".nameWithOwner",
            ],
            &cwd,
            GH_TIMEOUT_SECS,
            false,
        );
        if rc != Some(0) || out.is_empty() {
            let detail = if gh_err.is_empty() {
                "no output"
            } else {
                gh_err.as_str()
            };
            return make_fail(
                format!(
                    "`gh repo view` failed: {detail}. If this host is intentionally offline, rerun with --offline --default <branch> (gh skipped; all git-based BASE invariants still run)."
                ),
                1,
                cap_info.as_ref(),
                None,
            );
        }
        out
    };

    let Some(default_branch) = args
        .default_branch
        .clone()
        .or_else(|| default_branch_via_gh(&cwd))
    else {
        return make_fail(
            "could not derive default branch (pass --default)".to_string(),
            1,
            cap_info.as_ref(),
            None,
        );
    };

    let base_arg = args.base.as_deref().unwrap_or("");
    let c_base = canon_branch(base_arg, &cwd);
    let c_def = canon_branch(&default_branch, &cwd);
    if c_base == c_def {
        return make_fail(
            format!(
                "BASE ({base_arg:?} -> {c_base:?}) is the DEFAULT_BRANCH ({default_branch:?} -> {c_def:?}). Every per-finding PR is merged into BASE; if BASE is the default branch, fixes land straight on production and bypass both the anti-inflation gate and the human promotion review. Create a dedicated integration branch (e.g. `<maintainer>/fleet-integration`) off the current run's fork point and rerun."
            ),
            2,
            cap_info.as_ref(),
            None,
        );
    }

    if !branch_exists(&c_base, &cwd) {
        return make_fail(
            format!(
                "BASE {base_arg:?} is not a local or origin branch (tags and raw SHAs are not accepted as an integration BASE)."
            ),
            2,
            cap_info.as_ref(),
            None,
        );
    }

    let Some(mb) = merge_base(base_arg, &default_branch, &cwd) else {
        return make_fail(
            format!(
                "no merge-base between {base_arg:?} and {default_branch:?}; BASE does not appear to fork from the default branch's history."
            ),
            2,
            cap_info.as_ref(),
            None,
        );
    };

    if let Some(ref fp) = args.fork_point {
        let spec = format!("{fp}^{{commit}}");
        let (rc, fp_sha, _) = run_cmd_timeout(
            "git",
            &["rev-parse", "--verify", &spec],
            &cwd,
            GIT_TIMEOUT_SECS,
            true,
        );
        if rc != Some(0) {
            return make_fail(
                format!("--fork-point {fp:?} is not a commit."),
                1,
                cap_info.as_ref(),
                None,
            );
        }
        if fp_sha.trim() != mb {
            let mb_p = &mb[..mb.len().min(12)];
            let fp_t = fp_sha.trim();
            let fp_p = &fp_t[..fp_t.len().min(12)];
            return make_fail(
                format!(
                    "merge-base(BASE, {default_branch}) is {mb_p}, not the declared fork-point {fp_p} — BASE is stale or reused from an earlier run. Recreate BASE off the current fork point."
                ),
                2,
                cap_info.as_ref(),
                None,
            );
        }
    }

    if let (Some(tb), Some(td)) = (tip_sha(base_arg, &cwd), tip_sha(&default_branch, &cwd)) {
        if tb == td {
            let p = &tb[..tb.len().min(12)];
            warnings.push(format!(
                "BASE tip == default tip ({p}) — expected for a freshly created integration branch; confirm BASE is not another alias of the default."
            ));
        }
    }

    let mut stderr_lines: Vec<String> = warnings
        .iter()
        .map(|w| format!("preflight: WARN: {w}"))
        .collect();
    if !args.json {
        print_fallback_notes(cap_info.as_ref());
    }

    let mut payload = cap_info.clone().unwrap_or_default();
    payload.insert("ok".to_string(), json!(true));
    payload.insert("mode".to_string(), json!("write"));
    payload.insert("repo".to_string(), json!(repo_str));
    payload.insert("base".to_string(), json!(base_arg));
    payload.insert("default".to_string(), json!(default_branch));
    payload.insert("fork_point".to_string(), json!(mb));
    payload.insert("warnings".to_string(), json!(warnings));
    let val = Value::Object(payload);

    let stdout = if args.json {
        serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
    } else {
        let mb_p = &mb[..mb.len().min(12)];
        format!("preflight: OK — repo={repo_str}, base={base_arg}, default={default_branch}, fork_point={mb_p}")
    };
    let stderr = if stderr_lines.is_empty() {
        String::new()
    } else {
        stderr_lines.sort();
        stderr_lines.join("\n")
    };
    (0, val, stdout, stderr)
}

pub fn run_raw_cli(raw: &[OsString]) -> i32 {
    let args = match parse_raw_args(raw) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(msg) => {
            eprintln!("preflight.py: error: {msg}");
            return 1;
        }
    };
    let (code, _, stdout, stderr) = evaluate(&args);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    code
}
