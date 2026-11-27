//! Native Rust port of `runtime/scripts/dispatch-sign.py`:
//! coordinator Ed25519 dispatch-record and verifier-transcript signer (#135, #590, #608).

use crate::base64_codec::{canonical_json, decode_strict, encode};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use of_common::gitexec::{custody_env, git_binary};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const RECORD_FIELDS: &[&str] = &[
    "manifest_id",
    "contract_digest",
    "unit_class",
    "lighting",
    "nc_paths",
    "nc_command",
    "nc_artifact_sha256",
    "no_gh",
    "lane",
    "execute_nc",
    "allow_static_nc",
    "base_sha",
];

pub const PROFILE_FIELDS: &[&str] = &["profile", "parent_profile"];

pub const TRANSCRIPT_FIELDS: &[&str] = &[
    "unit",
    "manifest",
    "manifest_sha256",
    "args",
    "fatal",
    "notes",
    "exit",
    "toolchain",
    "timestamp",
];

pub const TOOLCHAIN_FILES: &[&str] = &[
    "verify.py",
    "_verify_sig.py",
    "_verify_diff.py",
    "diff_scope.py",
    "ed25519.py",
    "dispatch-sign.py",
    "inventory.py",
    "gitexec.py",
];

pub const PARENT_ENV: &[&str] = &[
    "OPEN_FLEET_PARENT_PROFILE",
    "ORCA_PARENT_PROFILE",
    "OPEN_FLEET_SANDBOX_PROFILE",
    "ORCA_SANDBOX_PROFILE",
];

fn profile_rank(p: &str) -> Option<u8> {
    match p {
        "ro" => Some(0),
        "rw" => Some(1),
        "danger" => Some(2),
        _ => None,
    }
}

pub fn effective_parent(
    explicit: &[Option<&str>],
    env_override: Option<&std::collections::HashMap<String, String>>,
) -> Result<Option<String>, String> {
    let mut present: Vec<String> = Vec::new();
    for item in explicit.iter().flatten() {
        let t = item.trim();
        if !t.is_empty() {
            present.push(t.to_string());
        }
    }
    for &k in PARENT_ENV {
        let val = match env_override {
            Some(m) => m.get(k).cloned(),
            None => env::var(k).ok(),
        };
        if let Some(v) = val {
            let t = v.trim();
            if !t.is_empty() {
                present.push(t.to_string());
            }
        }
    }
    let mut best: Option<(u8, String)> = None;
    for p in present {
        let Some(r) = profile_rank(&p) else {
            return Err(format!(
                "invalid parent profile {p:?} (expected one of ro, rw, danger)"
            ));
        };
        if best.as_ref().map(|(br, _)| r < *br).unwrap_or(true) {
            best = Some((r, p));
        }
    }
    Ok(best.map(|(_, s)| s))
}

pub fn check_profile_narrowing(
    profile: Option<&str>,
    parent_profile: Option<&str>,
    more_parents: &[Option<&str>],
    env_override: Option<&std::collections::HashMap<String, String>>,
) -> Result<(), String> {
    if let Some(p) = profile {
        if profile_rank(p).is_none() {
            return Err(format!(
                "invalid profile {p:?} (expected one of ro, rw, danger)"
            ));
        }
    }
    let mut explicit = vec![parent_profile];
    explicit.extend_from_slice(more_parents);
    let eff_parent = effective_parent(&explicit, env_override)?;
    if let (Some(p), Some(ep)) = (profile, eff_parent.as_deref()) {
        if profile_rank(p).unwrap_or(0) > profile_rank(ep).unwrap_or(0) {
            return Err(format!(
                "privilege escalation refused: child profile '{p}' exceeds parent profile '{ep}' (monotonic narrowing requires ro <= rw <= danger)"
            ));
        }
    }
    Ok(())
}

pub fn signed_fields<'a>(record: &Map<String, Value>, fields: &'a [&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = fields.to_vec();
    if std::ptr::eq(fields, RECORD_FIELDS)
        && PROFILE_FIELDS
            .iter()
            .any(|&k| record.get(k).map(|v| !v.is_null()).unwrap_or(false))
    {
        out.extend_from_slice(PROFILE_FIELDS);
    }
    out
}

pub fn canonical_subset(record: &Map<String, Value>, fields: &[&str]) -> Map<String, Value> {
    let mut subset = Map::new();
    for k in signed_fields(record, fields) {
        if let Some(v) = record.get(k) {
            if !v.is_null() {
                subset.insert(k.to_string(), v.clone());
            }
        }
    }
    if let Some(Value::Array(arr)) = subset.get("nc_paths").cloned() {
        let mut sorted: Vec<String> = arr
            .into_iter()
            .map(|x| match x {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .collect();
        sorted.sort();
        subset.insert(
            "nc_paths".to_string(),
            Value::Array(sorted.into_iter().map(Value::String).collect()),
        );
    }
    subset
}

pub fn canonical_record(record: &Map<String, Value>, fields: &[&str]) -> Vec<u8> {
    let subset = Value::Object(canonical_subset(record, fields));
    canonical_json(&subset).into_bytes()
}

pub fn publickey_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed);
    sk.verifying_key().to_bytes()
}

pub fn sign_bytes(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    sk.sign(message).to_bytes()
}

pub fn verify_bytes(sig: &[u8], message: &[u8], pub_bytes: &[u8]) -> bool {
    let Ok(pub_arr): Result<[u8; 32], _> = pub_bytes.try_into() else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(message, &signature).is_ok()
}

pub fn envelope(seed: &[u8; 32], record: &Map<String, Value>, fields: &[&str]) -> Value {
    let msg = canonical_record(record, fields);
    let sig = sign_bytes(seed, &msg);
    let mut rec_out = Map::new();
    for k in signed_fields(record, fields) {
        if let Some(v) = record.get(k) {
            if !v.is_null() {
                rec_out.insert(k.to_string(), v.clone());
            }
        }
    }
    json!({
        "record": Value::Object(rec_out),
        "sig_b64": encode(&sig),
    })
}

fn resolve_abs_path(path: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(path) {
        return c;
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    // Canonicalize deepest existing ancestor and re-append the non-existent suffix
    let mut suffix: Vec<OsString> = Vec::new();
    let mut cur = abs.as_path();
    while !cur.exists() {
        if let Some(name) = cur.file_name() {
            suffix.push(name.to_os_string());
        }
        match cur.parent() {
            Some(p) if p != cur => cur = p,
            _ => break,
        }
    }
    let mut base = fs::canonicalize(cur).unwrap_or_else(|_| cur.to_path_buf());
    for part in suffix.into_iter().rev() {
        base.push(part);
    }
    base
}

pub fn in_unignored_worktree(path: &Path) -> bool {
    let resolved = resolve_abs_path(path);
    let mut probe = resolved.parent().unwrap_or(&resolved).to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) if p != probe => probe = p.to_path_buf(),
            _ => break,
        }
    }
    let mut under_git = false;
    let mut ancestor = probe.clone();
    loop {
        if ancestor.join(".git").exists() {
            under_git = true;
            break;
        }
        match ancestor.parent() {
            Some(p) if p != ancestor => ancestor = p.to_path_buf(),
            _ => break,
        }
    }

    let base_env = custody_env(&[]);
    let mut env_probe = base_env.clone();
    for var in ["GIT_DIR", "GIT_WORK_TREE"] {
        if let Some(val) = env::var_os(var) {
            env_probe.push((OsString::from(var), val));
        }
    }

    let mut from_env = false;
    if !under_git {
        let Ok(git) = git_binary() else {
            return false;
        };
        let top = Command::new(git)
            .args(["rev-parse", "--show-toplevel"])
            .current_dir(&probe)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .envs(env_probe.iter().cloned())
            .output();
        let Ok(out) = top else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        let tl_raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if tl_raw.is_empty() {
            return false;
        }
        let toplevel = resolve_abs_path(Path::new(&tl_raw));
        under_git = resolved == toplevel || resolved.starts_with(&toplevel);
        from_env = under_git;
    }

    if !under_git {
        return false;
    }

    let Ok(git) = git_binary() else {
        return true;
    };
    let check_env = if from_env { &env_probe } else { &base_env };
    let check = Command::new(git)
        .args(["check-ignore", "-q", "--"])
        .arg(&resolved)
        .current_dir(&probe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(check_env.iter().cloned())
        .output();
    match check {
        Ok(out) => out.status.code() != Some(0),
        Err(_) => true,
    }
}

pub fn read_seed(key: Option<&Path>) -> Result<[u8; 32], String> {
    let key_path: PathBuf = match key {
        Some(p) => p.to_path_buf(),
        None => {
            let env_val = env::var("OPEN_FLEET_SIGNING_SEED")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    env::var("ORCA_DISPATCH_SIGNING_SEED")
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                })
                .unwrap_or_default();
            let trimmed = env_val.trim();
            if trimmed.is_empty() {
                return Err(
                    "missing --key and neither OPEN_FLEET_SIGNING_SEED nor ORCA_DISPATCH_SIGNING_SEED is set"
                        .to_string(),
                );
            }
            if trimmed.len() == 64 {
                if let Ok(bytes) = hex::decode(trimmed) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        eprintln!(
                            "seed custody: environment seed (OPEN_FLEET_SIGNING_SEED/ORCA_DISPATCH_SIGNING_SEED)"
                        );
                        return Ok(arr);
                    }
                }
            }
            PathBuf::from(trimmed)
        }
    };

    #[cfg(unix)]
    let mode_bits = {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&key_path)
            .map_err(|exc| format!("cannot read a hex seed from {}: {exc}", key_path.display()))?;
        let m = meta.permissions().mode() & 0o7777;
        if (m & 0o077) != 0 {
            return Err(format!(
                "seed custody: {} is mode {:04o} — readable beyond its owner, so any signature it makes is unattributable; refusing (chmod 0600, or gen-key anew)",
                key_path.display(),
                m
            ));
        }
        m
    };
    #[cfg(not(unix))]
    let mode_bits: u32 = {
        let _ = fs::metadata(&key_path)
            .map_err(|exc| format!("cannot read a hex seed from {}: {exc}", key_path.display()))?;
        0o600
    };

    if in_unignored_worktree(&key_path) {
        return Err(format!(
            "seed custody: {} is inside a git work tree that does not ignore it — one `git add -A` (or a past one) makes it public; refusing (move it out of the repo or git-ignore it)",
            key_path.display()
        ));
    }
    let text = fs::read_to_string(&key_path)
        .map_err(|exc| format!("cannot read a hex seed from {}: {exc}", key_path.display()))?;
    let raw = hex::decode(text.trim())
        .map_err(|exc| format!("cannot read a hex seed from {}: {exc}", key_path.display()))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "key must be a 32-byte hex seed".to_string())?;
    eprintln!(
        "seed custody: {} mode {:04o}, outside any unignored work tree",
        key_path.display(),
        mode_bits
    );
    Ok(arr)
}

pub fn gen_key(out: &Path, in_repo_ok: bool) -> i32 {
    if in_unignored_worktree(out) && !in_repo_ok {
        eprintln!(
            "dispatch-sign: REFUSING to write a private seed at {}",
            out.display()
        );
        eprintln!("  the path is (or could not be proven NOT) inside a git work tree and is NOT");
        eprintln!("  verified git-ignored — one `git add -A` would commit the key and void every");
        eprintln!("  signed-dispatch guarantee.");
        eprintln!("  pick an out-of-repo path (e.g. ~/.open-fleet/dispatch-key), git-ignore it,");
        eprintln!("  or pass --in-repo-ok if you really mean it.");
        return 2;
    }
    let mut seed = [0u8; 32];
    if let Err(err) = getrandom::getrandom(&mut seed) {
        eprintln!("dispatch-sign: csprng failed: {err}");
        return 1;
    }
    let pub_bytes = publickey_bytes(&seed);
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!("dispatch-sign: cannot create parent dir: {err}");
                return 1;
            }
        }
    }
    let seed_line = format!("{}\n", hex::encode(seed));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(out)
        {
            Ok(f) => f,
            Err(err) => {
                eprintln!("dispatch-sign: cannot write {}: {err}", out.display());
                return 1;
            }
        };
        let rc = unsafe { libc::fchmod(f.as_raw_fd(), 0o600) };
        if rc != 0 {
            eprintln!(
                "dispatch-sign: fchmod 0600 failed on {}: {}",
                out.display(),
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if let Err(err) = f.write_all(seed_line.as_bytes()) {
            eprintln!("dispatch-sign: write failed: {err}");
            return 1;
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = fs::write(out, seed_line) {
            eprintln!("dispatch-sign: cannot write {}: {err}", out.display());
            return 1;
        }
    }

    let mut pub_os = out.as_os_str().to_os_string();
    pub_os.push(".pub");
    let pub_path = PathBuf::from(pub_os);
    if let Err(err) = fs::write(&pub_path, format!("{}\n", hex::encode(pub_bytes))) {
        eprintln!("dispatch-sign: cannot write {}: {err}", pub_path.display());
        return 1;
    }
    eprintln!(
        "private seed: {} (0600 — keep OFF the graded worker)",
        out.display()
    );
    eprintln!(
        "public key:   {} (commit as .orca/dispatch-pubkey to enforce)",
        pub_path.display()
    );
    0
}

fn find_scripts_dir(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(p) = env::var("OPEN_FLEET_SCRIPTS_DIR") {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    if let Ok(cwd) = env::current_dir() {
        if let Some(root) = of_install::find_catalog_root(&cwd) {
            let sd = root.join("runtime/scripts");
            if sd.is_dir() {
                return Some(sd);
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent();
        while let Some(d) = cur {
            if let Some(root) = of_install::find_catalog_root(d) {
                let sd = root.join("runtime/scripts");
                if sd.is_dir() {
                    return Some(sd);
                }
            }
            cur = d.parent();
        }
    }
    None
}

pub fn toolchain_mismatch(
    record: &Map<String, Value>,
    scripts_dir: Option<&Path>,
) -> Option<String> {
    let files = record
        .get("toolchain")
        .and_then(|v| v.as_object())
        .and_then(|t| t.get("files"))
        .and_then(|f| f.as_object());
    let Some(files) = files else {
        return Some(
            "verdict object names no toolchain.files — which verifier produced it is unknown; sign only a verdict object you produced (h409 O-2.4)".to_string(),
        );
    };
    let dir = find_scripts_dir(scripts_dir);
    for &name in TOOLCHAIN_FILES {
        let signed = files.get(name).and_then(|v| v.as_str());
        let Some(ref sd) = dir else {
            return Some(format!(
                "{name} is absent beside this signer, so the verdict's toolchain cannot be re-hashed"
            ));
        };
        let bytes = match fs::read(sd.join(name)) {
            Ok(b) => b,
            Err(_) => {
                return Some(format!(
                    "{name} is absent beside this signer, so the verdict's toolchain cannot be re-hashed"
                ));
            }
        };
        let here = hex::encode(Sha256::digest(&bytes));
        let Some(signed_s) = signed else {
            return Some(format!(
                "verdict toolchain.files does not name {name} — a partial set binds no verifier"
            ));
        };
        if signed_s != here {
            let s_pre = &signed_s[..signed_s.len().min(12)];
            let h_pre = &here[..here.len().min(12)];
            return Some(format!(
                "verdict toolchain.files pins {name} at {s_pre}…, not the file beside this signer ({h_pre}…) — a different verifier produced it; sign only a verdict object you produced (h409 O-2.4)"
            ));
        }
    }
    None
}

pub struct SignArgs {
    pub key: Option<PathBuf>,
    pub manifest_id: String,
    pub contract_digest: String,
    pub unit_class: String,
    pub lighting: Option<String>,
    pub nc_paths: Option<Vec<String>>,
    pub nc_command: Option<String>,
    pub nc_artifact_sha256: Option<String>,
    pub no_gh: bool,
    pub lane: Option<String>,
    pub execute_nc: bool,
    pub allow_static_nc: bool,
    pub base_sha: Option<String>,
    pub profile: Option<String>,
    pub parent_profile: Option<String>,
}

pub fn cmd_sign(args: &SignArgs) -> i32 {
    if let Some(ref lane) = args.lane {
        if !matches!(lane.as_str(), "A" | "B" | "0") {
            eprintln!("dispatch-sign: invalid --lane {lane:?} (choose from 'A', 'B', '0')");
            return 2;
        }
    }
    let mut record = Map::new();
    record.insert(
        "manifest_id".to_string(),
        Value::String(args.manifest_id.clone()),
    );
    record.insert(
        "contract_digest".to_string(),
        Value::String(args.contract_digest.clone()),
    );
    record.insert(
        "unit_class".to_string(),
        Value::String(args.unit_class.clone()),
    );
    if let Some(ref v) = args.lighting {
        record.insert("lighting".to_string(), Value::String(v.clone()));
    }
    if let Some(ref paths) = args.nc_paths {
        record.insert(
            "nc_paths".to_string(),
            Value::Array(paths.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(ref v) = args.nc_command {
        record.insert("nc_command".to_string(), Value::String(v.clone()));
    }
    if let Some(ref v) = args.nc_artifact_sha256 {
        record.insert("nc_artifact_sha256".to_string(), Value::String(v.clone()));
    }
    if args.no_gh {
        record.insert("no_gh".to_string(), Value::Bool(true));
    }
    if let Some(ref v) = args.lane {
        record.insert("lane".to_string(), Value::String(v.clone()));
    }
    if args.execute_nc {
        record.insert("execute_nc".to_string(), Value::Bool(true));
    }
    if args.allow_static_nc {
        record.insert("allow_static_nc".to_string(), Value::Bool(true));
    }
    if let Some(ref v) = args.base_sha {
        record.insert("base_sha".to_string(), Value::String(v.clone()));
    }
    if let Some(ref v) = args.profile {
        record.insert("profile".to_string(), Value::String(v.clone()));
    }
    if let Some(ref v) = args.parent_profile {
        record.insert("parent_profile".to_string(), Value::String(v.clone()));
    }

    let rec_prof = record.get("profile").and_then(|v| v.as_str());
    let rec_parent = record.get("parent_profile").and_then(|v| v.as_str());
    if let Err(reason) = check_profile_narrowing(
        rec_prof,
        args.parent_profile.as_deref(),
        &[rec_parent],
        None,
    ) {
        eprintln!("dispatch-sign: {reason}");
        return 2;
    }

    let seed = match read_seed(args.key.as_deref()) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("dispatch-sign: {err}");
            return 1;
        }
    };
    let env_val = envelope(&seed, &record, RECORD_FIELDS);
    println!(
        "{}",
        serde_json::to_string_pretty(&env_val).unwrap_or_else(|_| "{}".to_string())
    );
    0
}

pub struct VerifyArgs {
    pub record_ref: Option<String>,
    pub pubkey_ref: Option<String>,
    pub key_ref: Option<PathBuf>,
    pub profile: Option<String>,
    pub parent_profile: Option<String>,
}

pub fn cmd_verify(args: &VerifyArgs) -> i32 {
    let mut env_obj: Option<Map<String, Value>> = None;
    let mut rec_obj: Map<String, Value> = Map::new();
    if let Some(ref rref) = args.record_ref {
        let parsed: Result<Value, String> = if rref.trim_start().starts_with('{') {
            serde_json::from_str(rref).map_err(|e| e.to_string())
        } else {
            fs::read_to_string(rref)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        };
        let val = match parsed {
            Ok(v) => v,
            Err(exc) => {
                eprintln!("dispatch-sign: cannot read dispatch record {rref}: {exc}");
                return 2;
            }
        };
        let Some(map) = val.as_object() else {
            eprintln!("dispatch-sign: dispatch record must be an envelope with a 'record' object");
            return 2;
        };
        let Some(rec) = map.get("record").and_then(|v| v.as_object()) else {
            eprintln!("dispatch-sign: dispatch record must be an envelope with a 'record' object");
            return 2;
        };
        rec_obj = rec.clone();
        env_obj = Some(map.clone());
    }

    if env_obj.is_some() {
        if let Some(ref prof) = args.profile {
            let rec_profile = rec_obj.get("profile").and_then(|v| v.as_str());
            let rec_profile_raw = rec_obj.get("profile");
            if rec_profile_raw.is_none() || rec_profile_raw == Some(&Value::Null) {
                eprintln!(
                    "dispatch-sign: --profile {prof:?} requested, but signed dispatch record carries no profile"
                );
                return 2;
            }
            let Some(rp) = rec_profile else {
                eprintln!(
                    "dispatch-sign: signed dispatch record carries invalid profile {:?}",
                    rec_profile_raw
                );
                return 2;
            };
            if profile_rank(rp).is_none() {
                eprintln!("dispatch-sign: signed dispatch record carries invalid profile {rp:?}");
                return 2;
            }
            if profile_rank(prof).is_none() {
                eprintln!(
                    "dispatch-sign: invalid profile {prof:?} (expected one of ro, rw, danger)"
                );
                return 2;
            }
            if prof != rp {
                eprintln!(
                    "dispatch-sign: requested profile '{prof}' does not match signed record profile '{rp}'"
                );
                return 2;
            }
        }
    }

    let eff_profile = args
        .profile
        .as_deref()
        .or_else(|| rec_obj.get("profile").and_then(|v| v.as_str()));
    let rec_parent = rec_obj.get("parent_profile").and_then(|v| v.as_str());
    if let Err(reason) = check_profile_narrowing(
        eff_profile,
        args.parent_profile.as_deref(),
        &[rec_parent],
        None,
    ) {
        eprintln!("dispatch-sign: {reason}");
        return 2;
    }

    if let Some(env_map) = env_obj {
        let pub_bytes: [u8; 32] = if let Some(ref pref) = args.pubkey_ref {
            let p_str = pref.trim();
            let raw = if p_str.len() == 64 && p_str.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex::decode(p_str).map_err(|e| e.to_string())
            } else {
                fs::read_to_string(p_str)
                    .map_err(|e| e.to_string())
                    .and_then(|s| hex::decode(s.trim()).map_err(|e| e.to_string()))
            };
            match raw.and_then(|b| {
                <[u8; 32]>::try_from(b.as_slice())
                    .map_err(|_| "pubkey must be 32 bytes".to_string())
            }) {
                Ok(arr) => arr,
                Err(exc) => {
                    eprintln!("dispatch-sign: cannot read pubkey {pref}: {exc}");
                    return 2;
                }
            }
        } else {
            let seed = match read_seed(args.key_ref.as_deref()) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("dispatch-sign: {err}");
                    return 2;
                }
            };
            publickey_bytes(&seed)
        };

        let Some(sig_b64) = env_map.get("sig_b64").and_then(|v| v.as_str()) else {
            eprintln!("dispatch-sign: malformed signature in envelope: missing sig_b64");
            return 2;
        };
        let sig = match decode_strict(sig_b64) {
            Ok(b) => b,
            Err(exc) => {
                eprintln!("dispatch-sign: malformed signature in envelope: {exc}");
                return 2;
            }
        };
        if !verify_bytes(&sig, &canonical_record(&rec_obj, RECORD_FIELDS), &pub_bytes) {
            eprintln!("dispatch-sign: signature verification FAILED");
            return 2;
        }
    }
    0
}

pub struct SignTranscriptArgs {
    pub key: Option<PathBuf>,
    pub transcript: PathBuf,
    pub out: Option<PathBuf>,
    pub scripts_dir: Option<PathBuf>,
}

pub fn cmd_sign_transcript(args: &SignTranscriptArgs) -> i32 {
    let seed = match read_seed(args.key.as_deref()) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("dispatch-sign: {err}");
            return 1;
        }
    };
    let text = match fs::read_to_string(&args.transcript) {
        Ok(t) => t,
        Err(exc) => {
            eprintln!(
                "dispatch-sign: cannot read a verdict object from {}: {exc}",
                args.transcript.display()
            );
            return 1;
        }
    };
    let val: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(exc) => {
            eprintln!(
                "dispatch-sign: cannot read a verdict object from {}: {exc}",
                args.transcript.display()
            );
            return 1;
        }
    };
    let Some(record) = val.as_object() else {
        eprintln!(
            "dispatch-sign: {} is not a JSON object",
            args.transcript.display()
        );
        return 1;
    };
    if record.contains_key("sig_b64") && record.contains_key("record") {
        eprintln!(
            "dispatch-sign: {} is already an envelope — sign the verdict object, not a signed one",
            args.transcript.display()
        );
        return 1;
    }
    let missing: Vec<&str> = TRANSCRIPT_FIELDS
        .iter()
        .copied()
        .filter(|&k| record.get(k).map(|v| v.is_null()).unwrap_or(true))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "dispatch-sign: verdict object is missing {:?} — refusing to sign an absence (want every one of {:?})",
            missing, TRANSCRIPT_FIELDS
        );
        return 1;
    }
    if let Some(mismatch) = toolchain_mismatch(record, args.scripts_dir.as_deref()) {
        eprintln!("dispatch-sign: {mismatch}");
        return 1;
    }
    let env_val = envelope(&seed, record, TRANSCRIPT_FIELDS);
    let out_text = serde_json::to_string_pretty(&env_val).unwrap_or_else(|_| "{}".to_string());
    if let Some(ref out_path) = args.out {
        if let Err(err) = fs::write(out_path, format!("{out_text}\n")) {
            eprintln!("dispatch-sign: cannot write {}: {err}", out_path.display());
            return 1;
        }
    } else {
        println!("{out_text}");
    }
    0
}
