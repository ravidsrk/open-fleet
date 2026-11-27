//! Hardened git execution, exact ref lookup, and isolated git custody,
//! mirroring `runtime/scripts/gitexec.py`.

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub const NO_SUBMODULE_CHILD: &str = "--ignore-submodules=dirty";
pub const REMOTE_TRACKING: &str = "refs/remotes/";
pub const LOCAL_BRANCH: &str = "refs/heads/";
const SYMREF_HOPS: usize = 5;
const ATTRIBUTES_FILE_LIMIT: usize = 1 << 20;

pub const DEFAULT_BASES: &[&str] = &[
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/main",
    "refs/remotes/origin/master",
    "refs/heads/main",
    "refs/heads/master",
];

const SELECTOR_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_ATTR_SOURCE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_EXTERNAL_DIFF",
];

const CUSTODY_CORE_KEYS: &[&str] = &[
    "filemode",
    "symlinks",
    "ignorecase",
    "precomposeunicode",
    "protecthfs",
    "protectntfs",
    "sparsecheckout",
    "sparsecheckoutcone",
    "autocrlf",
    "eol",
    "safecrlf",
    "checkroundtripencoding",
    "checkstat",
    "trustctime",
];

const HONOURABLE_EXTENSIONS: &[&str] = &[
    "objectformat",
    "compatobjectformat",
    "worktreeconfig",
    "refstorage",
    "relativeworktrees",
];

const PROVENANCE_VARS: &[&str] = &["OPEN_FLEET_PROVENANCE", "ORCA_PROVENANCE"];

#[derive(Debug, Clone)]
pub struct GitOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BaseResolution {
    pub commit: String,
    pub shown: String,
    pub local: Option<String>,
}

fn devnull() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

fn commit_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$").expect("valid commit id regex")
    })
}

fn abbrev_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{4,63}$").expect("valid abbrev id regex"))
}

fn filter_key_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(r"(?s)\Afilter\.(.+)\.[^.]+\z").expect("valid filter regex"))
}

fn merge_key_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(r"(?s)\Amerge\.(.+)\.[^.]+\z").expect("valid merge regex"))
}

fn diff_cmd_key_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(r"(?s)\Adiff\.(?:.+)\.(?:textconv|command)\z")
            .expect("valid diff cmd regex")
    })
}

pub fn git_binary() -> Result<&'static Path, String> {
    static GIT_BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    let found = GIT_BIN.get_or_init(|| {
        let path_var = env::var_os("PATH")?;
        let exts: &[&str] = if cfg!(windows) {
            &[".exe", ".cmd", ".bat", ""]
        } else {
            &[""]
        };
        for dir in env::split_paths(&path_var) {
            for ext in exts {
                let cand = dir.join(format!("git{ext}"));
                if cand.is_file() {
                    if let Ok(abs) = fs::canonicalize(&cand) {
                        return Some(abs);
                    }
                    return Some(cand);
                }
            }
        }
        None
    });
    found
        .as_deref()
        .ok_or_else(|| "git is not on PATH (resolved once, at startup)".to_string())
}

pub fn sound_lane() -> Option<String> {
    for var in PROVENANCE_VARS {
        if let Ok(val) = env::var(var) {
            if !val.trim().is_empty() {
                return Some(format!("{var}={val}"));
            }
        }
    }
    None
}

pub fn custody_env(blanks: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut env_map: BTreeMap<OsString, OsString> = BTreeMap::new();
    for (k, v) in env::vars_os() {
        let ks = k.to_string_lossy();
        if SELECTOR_ENV.contains(&ks.as_ref())
            || ks.starts_with("GIT_CONFIG_KEY_")
            || ks.starts_with("GIT_CONFIG_VALUE_")
        {
            continue;
        }
        env_map.insert(k, v);
    }

    let dn = devnull();
    let base_pairs: &[(&str, &str)] = &[
        ("core.fsmonitor", "false"),
        ("protocol.ext.allow", "never"),
        ("safe.directory", "*"),
        ("core.hooksPath", dn),
        ("diff.external", ""),
        ("core.alternateRefsCommand", "exit 0"),
        ("submodule.recurse", "false"),
        ("fetch.recurseSubmodules", "false"),
        ("status.submoduleSummary", "false"),
        ("log.showSignature", "false"),
        ("gpg.program", dn),
        ("gpg.openpgp.program", dn),
        ("gpg.x509.program", dn),
        ("gpg.ssh.program", dn),
        ("maintenance.auto", "false"),
        ("gc.auto", "0"),
    ];

    env_map.insert(
        OsString::from("GIT_NO_REPLACE_OBJECTS"),
        OsString::from("1"),
    );
    env_map.insert(OsString::from("GIT_GRAFT_FILE"), OsString::from(dn));
    env_map.insert(OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0"));
    env_map.insert(OsString::from("GIT_CONFIG_GLOBAL"), OsString::from(dn));
    env_map.insert(OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1"));
    env_map.insert(OsString::from("GIT_NO_LAZY_FETCH"), OsString::from("1"));
    env_map.insert(OsString::from("GIT_ALLOW_PROTOCOL"), OsString::from("file"));
    env_map.insert(OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1"));

    let mut idx = 0usize;
    for (k, v) in base_pairs {
        env_map.insert(
            OsString::from(format!("GIT_CONFIG_KEY_{idx}")),
            OsString::from(*k),
        );
        env_map.insert(
            OsString::from(format!("GIT_CONFIG_VALUE_{idx}")),
            OsString::from(*v),
        );
        idx += 1;
    }
    for (k, v) in blanks {
        env_map.insert(OsString::from(format!("GIT_CONFIG_KEY_{idx}")), k.clone());
        env_map.insert(OsString::from(format!("GIT_CONFIG_VALUE_{idx}")), v.clone());
        idx += 1;
    }
    env_map.insert(
        OsString::from("GIT_CONFIG_COUNT"),
        OsString::from(idx.to_string()),
    );
    env_map.into_iter().collect()
}

pub fn run_git_raw(
    lead: &[OsString],
    args: &[OsString],
    blanks: &[(OsString, OsString)],
) -> Result<GitOutput, String> {
    let git = git_binary()?;
    let mut cmd = Command::new(git);
    cmd.args(lead)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(custody_env(blanks));
    let out = cmd
        .output()
        .map_err(|err| format!("git failed to run: {err}"))?;
    Ok(GitOutput {
        code: out.status.code().unwrap_or(1),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

pub fn run_git_repo(
    repo: &Path,
    args: &[&str],
    blanks: &[(OsString, OsString)],
) -> Result<GitOutput, String> {
    refuse_blocking_files(repo)?;
    let lead = vec![OsString::from("-C"), repo.as_os_str().to_os_string()];
    let arg_vec: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_git_raw(&lead, &arg_vec, blanks)
}

#[cfg(unix)]
fn bytes_to_os(b: &[u8]) -> OsString {
    OsString::from_vec(b.to_vec())
}

#[cfg(not(unix))]
fn bytes_to_os(b: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(b).into_owned())
}

#[cfg(unix)]
fn os_to_bytes(s: &OsStr) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_to_bytes(s: &OsStr) -> Vec<u8> {
    s.to_string_lossy().as_bytes().to_vec()
}

pub fn driver_blanks(repo: &Path) -> Result<Vec<(OsString, OsString)>, String> {
    let out = run_git_repo(repo, &["config", "--list", "-z", "--name-only"], &[])?;
    if out.code != 0 {
        let why = String::from_utf8_lossy(&out.stderr);
        let snippet: String = why.trim().chars().take(200).collect();
        return Err(format!(
            "cannot read the repository's driver config, so its filter commands cannot be neutralised: git config --list exited {} in {}: {}",
            out.code,
            repo.display(),
            snippet
        ));
    }
    blank_pairs(&out.stdout)
}

fn blank_pairs(listing: &[u8]) -> Result<Vec<(OsString, OsString)>, String> {
    if !listing.is_empty() && !listing.ends_with(b"\0") {
        return Err("git config --list printed output that is not NUL-terminated keys".to_string());
    }
    let keys: Vec<&[u8]> = if listing.is_empty() {
        Vec::new()
    } else {
        listing[..listing.len() - 1].split(|&b| b == 0).collect()
    };
    if keys.iter().any(|k| k.is_empty()) {
        return Err("git config --list printed an empty key".to_string());
    }

    let mut pairs = Vec::new();
    let mut filt_seen: HashSet<Vec<u8>> = HashSet::new();
    let mut merge_seen: HashSet<Vec<u8>> = HashSet::new();
    let filter_blanks: &[(&[u8], &str)] = &[
        (b"clean", ""),
        (b"smudge", ""),
        (b"process", ""),
        (b"required", "false"),
    ];

    for key in keys {
        if let Some(caps) = filter_key_re().captures(key) {
            let drv = caps[1].to_vec();
            if filt_seen.insert(drv.clone()) {
                for (var, val) in filter_blanks {
                    let mut full = Vec::with_capacity(7 + drv.len() + 1 + var.len());
                    full.extend_from_slice(b"filter.");
                    full.extend_from_slice(&drv);
                    full.push(b'.');
                    full.extend_from_slice(var);
                    pairs.push((bytes_to_os(&full), OsString::from(*val)));
                }
            }
        } else if let Some(caps) = merge_key_re().captures(key) {
            let drv = caps[1].to_vec();
            if merge_seen.insert(drv.clone()) {
                let mut full = Vec::with_capacity(6 + drv.len() + 7);
                full.extend_from_slice(b"merge.");
                full.extend_from_slice(&drv);
                full.extend_from_slice(b".driver");
                pairs.push((bytes_to_os(&full), OsString::from("exit 1")));
            }
        } else if diff_cmd_key_re().is_match(key) {
            pairs.push((bytes_to_os(key), OsString::from("")));
        }
    }
    Ok(pairs)
}

// --- Exact ref lookup (W3-07) -------------------------------------------------------------------

type RefTable = HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>;
type GitConfigEntry = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

fn parse_ref_records(out: &[u8], namespace: &str) -> Result<RefTable, String> {
    if out.is_empty() {
        return Ok(HashMap::new());
    }
    let body = if out.ends_with(b"\0\n") {
        &out[..out.len() - 2]
    } else if out.ends_with(b"\0") {
        &out[..out.len() - 1]
    } else {
        return Err("the for-each-ref listing is not NUL-terminated records".to_string());
    };
    let ns_bytes = namespace.as_bytes();
    let mut listed = HashMap::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= body.len() {
        let is_sep = i + 1 < body.len() && body[i] == 0 && body[i + 1] == b'\n';
        let at_end = i == body.len();
        if is_sep || at_end {
            let record = &body[start..i];
            let fields: Vec<&[u8]> = record.split(|&b| b == 0).collect();
            if fields.len() != 3 || !fields[0].starts_with(ns_bytes) {
                return Err("the for-each-ref listing holds a malformed record".to_string());
            }
            let key = fields[0].to_vec();
            if listed.contains_key(&key) {
                return Err(format!(
                    "the for-each-ref listing names {:?} twice",
                    String::from_utf8_lossy(&key)
                ));
            }
            listed.insert(key, (fields[1].to_vec(), fields[2].to_vec()));
            if at_end {
                break;
            }
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    Ok(listed)
}

fn exact_ref_commit(
    repo: &Path,
    name: &str,
    namespace: &str,
    kind: &str,
    outside: &str,
) -> Result<(String, String), (String, String)> {
    let chk =
        run_git_repo(repo, &["check-ref-format", name], &[]).map_err(|e| (name.to_string(), e))?;
    if chk.code != 0 {
        return Err((
            name.to_string(),
            "is not a valid ref name: revision syntax (~1, ^, @{…}, :) names a commit relative to a ref, not a ref".to_string(),
        ));
    }
    let listing = run_git_repo(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(symref)%00%(objectname)%00",
            namespace,
        ],
        &[],
    )
    .map_err(|e| (name.to_string(), e))?;
    if listing.code != 0 {
        return Err((
            name.to_string(),
            "could not be looked up: git for-each-ref failed".to_string(),
        ));
    }
    let listed = parse_ref_records(&listing.stdout, namespace)
        .map_err(|bad| (name.to_string(), format!("could not be looked up: {bad}")))?;

    let ns_bytes = namespace.as_bytes();
    let mut target = name.as_bytes().to_vec();
    let mut resolved_oid: Option<Vec<u8>> = None;

    for _hop in 0..=SYMREF_HOPS {
        let Some((symbolic, oid)) = listed.get(&target) else {
            let t_str = String::from_utf8_lossy(&target).into_owned();
            let via = if target != name.as_bytes() {
                format!(" (through the symbolic ref to {t_str})")
            } else {
                String::new()
            };
            return Err((
                t_str.clone(),
                format!(
                    "names no {kind} that exists under exactly that name{via}: git's ref-name expansion (refs/heads/{t_str}, …) is never followed"
                ),
            ));
        };
        if symbolic.is_empty() {
            resolved_oid = Some(oid.clone());
            break;
        }
        let lead = vec![OsString::from("-C"), repo.as_os_str().to_os_string()];
        let args = vec![
            OsString::from("symbolic-ref"),
            OsString::from("-q"),
            OsString::from("--no-recurse"),
            bytes_to_os(&target),
        ];
        let sym = run_git_raw(&lead, &args, &[])
            .map_err(|e| (String::from_utf8_lossy(&target).into_owned(), e))?;
        let hop = if sym.code == 0 {
            if sym.stdout.ends_with(b"\n") {
                sym.stdout[..sym.stdout.len() - 1].to_vec()
            } else {
                sym.stdout
            }
        } else {
            Vec::new()
        };
        if hop.is_empty() || hop.contains(&b'\n') || hop.contains(&0) {
            return Err((
                String::from_utf8_lossy(&target).into_owned(),
                "is a symbolic ref whose chain cannot be read one hop at a time here (git symbolic-ref --no-recurse, git 2.39+): refused rather than trusted on its recursively resolved target".to_string(),
            ));
        }
        if !hop.starts_with(ns_bytes) {
            let h_str = String::from_utf8_lossy(&hop).into_owned();
            return Err((
                h_str.clone(),
                format!("is a symbolic ref to {h_str}, which {outside}"),
            ));
        }
        target = hop;
    }

    let t_str = String::from_utf8_lossy(&target).into_owned();
    let Some(oid_bytes) = resolved_oid else {
        return Err((
            t_str,
            format!("is a symbolic-ref chain longer than {SYMREF_HOPS} hops"),
        ));
    };
    let oid = String::from_utf8_lossy(&oid_bytes).into_owned();
    let peeled_arg = format!("{oid}^{{commit}}");
    let peel = run_git_repo(repo, &["rev-parse", "--verify", "-q", &peeled_arg], &[])
        .map_err(|e| (t_str.clone(), e))?;
    let commit = String::from_utf8_lossy(&peel.stdout).trim().to_string();
    if peel.code != 0 || !commit_id_re().is_match(&commit) {
        return Err((
            t_str.clone(),
            format!("reaches {t_str}, which points at no commit"),
        ));
    }
    Ok((commit, t_str))
}

pub fn remote_tracking_commit(
    repo: &Path,
    name: &str,
) -> Result<(String, String), (String, String)> {
    if name.is_empty() || name.starts_with('-') {
        return Err((
            name.to_string(),
            "is empty or option-shaped, not a commit id or a ref".to_string(),
        ));
    }
    let lower = name.to_ascii_lowercase();
    if commit_id_re().is_match(&lower) {
        let arg = format!("{lower}^{{commit}}");
        let out = run_git_repo(repo, &["rev-parse", "--verify", "-q", &arg], &[])
            .map_err(|e| (name.to_string(), e))?;
        let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.code != 0 || got != lower {
            return Err((
                name.to_string(),
                "is spelled as a commit id but names no commit object here (an id is read as an object id only, never as a ref of that spelling)".to_string(),
            ));
        }
        return Ok((lower.clone(), lower));
    }
    if !name.starts_with(REMOTE_TRACKING) {
        return Err((
            name.to_string(),
            "is neither a commit id nor a full remote-tracking ref name (refs/remotes/…): a local branch, tag, HEAD or short name is one the checked change can move".to_string(),
        ));
    }
    exact_ref_commit(
        repo,
        name,
        REMOTE_TRACKING,
        "remote-tracking ref",
        "is not remote-tracking (a local branch the checked change can move)",
    )
}

pub fn local_branch_commit(repo: &Path, name: &str) -> Result<(String, String), (String, String)> {
    if !name.starts_with(LOCAL_BRANCH) {
        return Err((
            name.to_string(),
            "is not a full local branch name (refs/heads/…)".to_string(),
        ));
    }
    exact_ref_commit(
        repo,
        name,
        LOCAL_BRANCH,
        "local branch",
        "is not a local branch",
    )
}

fn abbreviated_commit(repo: &Path, prefix: &str) -> Result<String, String> {
    let arg = format!("--disambiguate={prefix}");
    let out = run_git_repo(repo, &["rev-parse", &arg], &[])?;
    let mut commits = Vec::new();
    if out.code == 0 {
        for oid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            if commit_id_re().is_match(oid) {
                let kind = run_git_repo(repo, &["cat-file", "-t", oid], &[])?;
                if kind.code == 0 && String::from_utf8_lossy(&kind.stdout).trim() == "commit" {
                    commits.push(oid.to_string());
                }
            }
        }
    }
    if commits.len() != 1 {
        return Err(format!(
            "abbreviates {} commit objects here, not one (an abbreviated id is read as an object id only, never as a ref of that spelling)",
            commits.len()
        ));
    }
    Ok(commits.remove(0))
}

fn short_ref(r: &str) -> String {
    for prefix in [REMOTE_TRACKING, LOCAL_BRANCH] {
        if let Some(rest) = r.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    r.to_string()
}

pub fn base_commit(repo: &Path, base: Option<&str>) -> Result<BaseResolution, String> {
    if let Some(b) = base {
        if b.is_empty() || b.starts_with('-') {
            return Err(format!(
                "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} is empty or option-shaped"
            ));
        }
        let lower = b.to_ascii_lowercase();
        if commit_id_re().is_match(&lower) || b.starts_with(REMOTE_TRACKING) {
            return match remote_tracking_commit(repo, b) {
                Ok((commit, _)) => Ok(BaseResolution {
                    commit,
                    shown: b.to_string(),
                    local: None,
                }),
                Err((_, why)) => Err(format!(
                    "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} {why}"
                )),
            };
        }
        if b == "HEAD" {
            let out = run_git_repo(repo, &["rev-parse", "--verify", "-q", "HEAD^{commit}"], &[])?;
            let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.code != 0 || !commit_id_re().is_match(&commit) {
                return Err(format!(
                    "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} names no commit (an unborn or detached-broken HEAD)"
                ));
            }
            return Ok(BaseResolution {
                commit,
                shown: b.to_string(),
                local: Some("HEAD, a LOCAL name".to_string()),
            });
        }
        if abbrev_id_re().is_match(&lower) {
            return match abbreviated_commit(repo, &lower) {
                Ok(commit) => Ok(BaseResolution {
                    commit,
                    shown: b.to_string(),
                    local: Some("an abbreviated commit id".to_string()),
                }),
                Err(why) => Err(format!(
                    "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} {why}"
                )),
            };
        }
        if b.starts_with(LOCAL_BRANCH) || !(b.starts_with("refs/") || b.contains('/')) {
            let full = if b.starts_with(LOCAL_BRANCH) {
                b.to_string()
            } else {
                format!("{LOCAL_BRANCH}{b}")
            };
            return match local_branch_commit(repo, &full) {
                Ok((commit, _)) => Ok(BaseResolution {
                    commit,
                    shown: b.to_string(),
                    local: Some("a LOCAL branch".to_string()),
                }),
                Err((_, why)) => Err(format!(
                    "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} ({full}) {why}"
                )),
            };
        }
        if b.starts_with("refs/") {
            return Err(format!(
                "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} is neither remote-tracking (refs/remotes/…) nor a local branch (refs/heads/…): a tag or other ref is no base"
            ));
        }
        let full = format!("{REMOTE_TRACKING}{b}");
        return match remote_tracking_commit(repo, &full) {
            Ok((commit, _)) => Ok(BaseResolution {
                commit,
                shown: b.to_string(),
                local: None,
            }),
            Err((_, why)) => Err(format!(
                "base ref {b:?} is not resolvable by its exact name (shallow clone or missing fetch?): {b:?} ({full}) {why}"
            )),
        };
    }

    let mut skipped = Vec::new();
    for name in DEFAULT_BASES {
        let is_local = name.starts_with(LOCAL_BRANCH);
        let res = if is_local {
            local_branch_commit(repo, name)
        } else {
            remote_tracking_commit(repo, name)
        };
        match res {
            Ok((commit, target)) => {
                return Ok(BaseResolution {
                    commit,
                    shown: short_ref(&target),
                    local: if is_local {
                        Some("a LOCAL branch".to_string())
                    } else {
                        None
                    },
                });
            }
            Err((_, why)) => skipped.push(format!("{name} {why}")),
        }
    }
    let tried: Vec<String> = DEFAULT_BASES.iter().map(|n| short_ref(n)).collect();
    Err(format!(
        "no base ref could be resolved (tried {}): {}",
        tried.join(", "),
        skipped.join("; ")
    ))
}

// --- Blocking-file pre-check (FIFO/device refusal before git runs) ------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Missing,
    Regular,
    Dir,
    Other,
}

fn path_kind(path: &Path) -> PathKind {
    match fs::metadata(path) {
        Ok(m) => {
            if m.is_file() {
                PathKind::Regular
            } else if m.is_dir() {
                PathKind::Dir
            } else {
                PathKind::Other
            }
        }
        Err(_) => PathKind::Missing,
    }
}

#[cfg(unix)]
fn open_regular_nonblock(
    path: &Path,
    nofollow: bool,
    limit: Option<usize>,
) -> Result<Option<(Vec<u8>, fs::Metadata)>, String> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let bytes = os_to_bytes(path.as_os_str());
    let Ok(cpath) = CString::new(bytes) else {
        return Err(format!(
            "git custody: path contains NUL: {}",
            path.display()
        ));
    };
    let mut flags = libc::O_RDONLY | libc::O_NONBLOCK;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "git custody: cannot read {:?} as a regular file: {err}",
            path.display()
        ));
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|err| format!("git custody: cannot stat {:?}: {err}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "git custody: {:?} is not a regular file",
            path.display()
        ));
    }
    if let Some(lim) = limit {
        if meta.len() as usize > lim {
            return Err(format!(
                "git custody: {:?} is larger than {lim} bytes",
                path.display()
            ));
        }
        let mut buf = Vec::new();
        let mut handle = (&mut file).take((lim + 1) as u64);
        handle
            .read_to_end(&mut buf)
            .map_err(|err| format!("git custody: read failed for {:?}: {err}", path.display()))?;
        if buf.len() > lim {
            return Err(format!(
                "git custody: {:?} is larger than {lim} bytes",
                path.display()
            ));
        }
        Ok(Some((buf, meta)))
    } else {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|err| format!("git custody: read failed for {:?}: {err}", path.display()))?;
        Ok(Some((buf, meta)))
    }
}

#[cfg(not(unix))]
fn open_regular_nonblock(
    path: &Path,
    nofollow: bool,
    limit: Option<usize>,
) -> Result<Option<(Vec<u8>, fs::Metadata)>, String> {
    let meta = match if nofollow {
        fs::symlink_metadata(path)
    } else {
        fs::metadata(path)
    } {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "git custody: cannot read {:?}: {e}",
                path.display()
            ))
        }
    };
    if !meta.is_file() {
        return Err(format!(
            "git custody: {:?} is not a regular file",
            path.display()
        ));
    }
    if let Some(lim) = limit {
        if meta.len() as usize > lim {
            return Err(format!(
                "git custody: {:?} is larger than {lim} bytes",
                path.display()
            ));
        }
    }
    let data = fs::read(path)
        .map_err(|e| format!("git custody: cannot read {:?}: {e}", path.display()))?;
    if let Some(lim) = limit {
        if data.len() > lim {
            return Err(format!(
                "git custody: {:?} is larger than {lim} bytes",
                path.display()
            ));
        }
    }
    Ok(Some((data, meta)))
}

fn peek_regular(path: &Path, limit: usize) -> Option<Vec<u8>> {
    open_regular_nonblock(path, false, Some(limit))
        .ok()
        .flatten()
        .map(|(b, _)| b)
}

const TRIMMABLE: &[u8] = b" \t\n\x0b\x0c\r";
const GIT_SPACE_SETS: &[&[u8]] = &[b" \t\n\r", b" \t\n\r\x0b\x0c"];

#[derive(Clone, Copy)]
enum InnerWs {
    Space,
    Verbatim,
    Collapse,
}

fn spellings(raw: &[u8]) -> BTreeSet<Vec<u8>> {
    let lead_trim = raw
        .iter()
        .take_while(|b| TRIMMABLE.contains(b))
        .count()
        .min(16);
    let trail_trim = raw
        .iter()
        .rev()
        .take_while(|b| TRIMMABLE.contains(b))
        .count()
        .min(16);
    let mut out = BTreeSet::new();
    for i in 0..=lead_trim {
        for j in 0..=trail_trim {
            if i + j <= raw.len() {
                out.insert(raw[i..raw.len() - j].to_vec());
            }
        }
    }
    out
}

fn parse_git_config(data: &[u8], space: &[u8], inner: InnerWs) -> Vec<GitConfigEntry> {
    let mut entries = Vec::new();
    if data.contains(&0) {
        return entries;
    }
    let mut slice = data;
    if slice.starts_with(&[0xEF, 0xBB, 0xBF]) {
        slice = &slice[3..];
    }
    let mut norm = Vec::with_capacity(slice.len());
    let mut k = 0;
    while k < slice.len() {
        if k + 1 < slice.len() && slice[k] == b'\r' && slice[k + 1] == b'\n' {
            norm.push(b'\n');
            k += 2;
        } else {
            norm.push(slice[k]);
            k += 1;
        }
    }

    let n = norm.len();
    let mut i = 0usize;
    let nxt = |idx: &mut usize| -> Option<u8> {
        if *idx >= n {
            *idx += 1;
            None
        } else {
            let b = norm[*idx];
            *idx += 1;
            Some(b)
        }
    };

    let mut section: Vec<u8> = Vec::new();
    let mut comment = false;
    loop {
        let Some(mut c) = nxt(&mut i) else {
            return entries;
        };
        if c == b'\n' {
            comment = false;
            continue;
        }
        if comment || space.contains(&c) {
            continue;
        }
        if c == b'#' || c == b';' {
            comment = true;
            continue;
        }
        if c == b'[' {
            let mut name = Vec::new();
            loop {
                let Some(ch) = nxt(&mut i) else {
                    return entries;
                };
                if ch == b'\n' {
                    return entries;
                }
                if ch == b']' {
                    break;
                }
                if space.contains(&ch) {
                    let mut cur = ch;
                    while space.contains(&cur) {
                        match nxt(&mut i) {
                            Some(nx) => cur = nx,
                            None => return entries,
                        }
                    }
                    if cur != b'"' {
                        return entries;
                    }
                    loop {
                        let Some(sc) = nxt(&mut i) else {
                            return entries;
                        };
                        if sc == b'\n' {
                            return entries;
                        }
                        if sc == b'"' {
                            break;
                        }
                        if sc == b'\\' {
                            let Some(esc) = nxt(&mut i) else {
                                return entries;
                            };
                            if esc == b'\n' {
                                return entries;
                            }
                        }
                    }
                    if nxt(&mut i) != Some(b']') {
                        return entries;
                    }
                    break;
                }
                if !(ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'.') {
                    return entries;
                }
                name.push(ch.to_ascii_lowercase());
            }
            if name.is_empty() {
                return entries;
            }
            if let Some(dot) = name.iter().position(|&b| b == b'.') {
                section = name[..dot].to_vec();
            } else {
                section = name;
            }
            continue;
        }
        if !c.is_ascii_alphabetic() {
            return entries;
        }
        let mut key = vec![c.to_ascii_lowercase()];
        let mut after: Option<u8>;
        loop {
            after = nxt(&mut i);
            match after {
                Some(ch) if ch.is_ascii_alphanumeric() || ch == b'-' => {
                    key.push(ch.to_ascii_lowercase());
                }
                _ => break,
            }
        }
        while matches!(after, Some(b' ') | Some(b'\t')) {
            after = nxt(&mut i);
        }
        match after {
            None | Some(b'\n') => {
                entries.push((section.clone(), key, None));
                continue;
            }
            Some(b'=') => {}
            _ => return entries,
        }
        let mut value = Vec::new();
        let mut quote = false;
        let mut blanks = Vec::new();
        let mut in_comment = false;
        loop {
            let Some(ch) = nxt(&mut i) else {
                if quote {
                    return entries;
                }
                break;
            };
            if ch == b'\n' {
                if quote {
                    return entries;
                }
                break;
            }
            if in_comment {
                continue;
            }
            if !quote {
                if ch == b';' || ch == b'#' {
                    in_comment = true;
                    continue;
                }
                if space.contains(&ch) {
                    if !value.is_empty() {
                        blanks.push(ch);
                    }
                    continue;
                }
            }
            if !blanks.is_empty() {
                match inner {
                    InnerWs::Space => value.extend(std::iter::repeat_n(b' ', blanks.len())),
                    InnerWs::Verbatim => value.extend_from_slice(&blanks),
                    InnerWs::Collapse => value.push(b' '),
                }
                blanks.clear();
            }
            if ch == b'\\' {
                let Some(esc) = nxt(&mut i) else {
                    return entries;
                };
                if esc == b'\n' {
                    continue;
                }
                let mapped = match esc {
                    b't' => b'\t',
                    b'b' => 0x08,
                    b'n' => b'\n',
                    b'\\' => b'\\',
                    b'"' => b'"',
                    _ => return entries,
                };
                value.push(mapped);
                continue;
            }
            if ch == b'"' {
                quote = !quote;
                continue;
            }
            c = ch;
            value.push(c);
        }
        entries.push((section.clone(), key, Some(value)));
    }
}

fn include_targets(cfg: &Path, data: &[u8]) -> Vec<PathBuf> {
    let mut vals: BTreeSet<Vec<u8>> = BTreeSet::new();
    for space in GIT_SPACE_SETS {
        for inner in [InnerWs::Space, InnerWs::Verbatim, InnerWs::Collapse] {
            for (sec, key, val) in parse_git_config(data, space, inner) {
                if (sec == b"include" || sec == b"includeif") && key == b"path" {
                    if let Some(v) = val {
                        for sp in spellings(&v) {
                            vals.insert(sp);
                        }
                    }
                }
            }
        }
    }
    let mut targets = BTreeSet::new();
    for sp in vals {
        let p_os = bytes_to_os(&sp);
        let p_str = p_os.to_string_lossy();
        if p_str.is_empty() || p_str.starts_with("%(prefix)/") {
            continue;
        }
        let resolved = if let Some(rest_tilde) = p_str.strip_prefix('~') {
            let (user, rest) = match rest_tilde.find('/') {
                Some(idx) => (&rest_tilde[..idx], Some(&rest_tilde[idx + 1..])),
                None => (rest_tilde, None),
            };
            let home = if user.is_empty() {
                env::var_os("HOME").map(PathBuf::from)
            } else {
                None
            };
            let Some(h) = home else {
                continue;
            };
            match rest {
                Some(r) => h.join(r),
                None => h,
            }
        } else {
            let pb = PathBuf::from(&p_os);
            if pb.is_absolute() {
                pb
            } else {
                cfg.parent().unwrap_or_else(|| Path::new(".")).join(pb)
            }
        };
        targets.insert(resolved);
    }
    targets.into_iter().collect()
}

fn relative_dirs(base: &Path, raw: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sp in spellings(raw) {
        if sp.is_empty() {
            continue;
        }
        let pb = PathBuf::from(bytes_to_os(&sp));
        let full = if pb.is_absolute() { pb } else { base.join(pb) };
        if path_kind(&full) == PathKind::Dir {
            out.push(full);
        }
    }
    out
}

fn discover_git_dirs(path: &Path) -> Result<Vec<(PathBuf, Vec<PathBuf>)>, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut d = if abs.is_dir() {
        abs
    } else {
        abs.parent().map(Path::to_path_buf).unwrap_or(abs)
    };
    loop {
        let dotgit = d.join(".git");
        let kind = path_kind(&dotgit);
        let mut gitdirs = Vec::new();
        if kind == PathKind::Dir {
            gitdirs.push(dotgit);
        } else if kind == PathKind::Regular {
            let got = peek_regular(&dotgit, 4096).unwrap_or_default();
            if let Some(rest) = got.strip_prefix(b"gitdir:") {
                gitdirs = relative_dirs(&d, rest);
            }
        } else if kind == PathKind::Missing
            && path_kind(&d.join("HEAD")) == PathKind::Regular
            && path_kind(&d.join("objects")) == PathKind::Dir
        {
            gitdirs.push(d.clone());
        }
        if !gitdirs.is_empty() || kind != PathKind::Missing {
            let mut out = Vec::new();
            for gd in gitdirs {
                let commondir = gd.join("commondir");
                let ckind = path_kind(&commondir);
                if ckind == PathKind::Other {
                    return Err(format!(
                        "git custody: {:?} is not a regular file, and git would block opening it",
                        commondir.display()
                    ));
                }
                let commons = if ckind == PathKind::Regular {
                    match peek_regular(&commondir, 4096) {
                        Some(raw) => relative_dirs(&gd, &raw),
                        None => vec![gd.clone()],
                    }
                } else {
                    vec![gd.clone()]
                };
                out.push((gd, commons));
            }
            return Ok(out);
        }
        let Some(parent) = d.parent() else {
            return Ok(Vec::new());
        };
        if parent == d {
            return Ok(Vec::new());
        }
        d = parent.to_path_buf();
    }
}

pub fn refuse_blocking_files(path: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    for (gd, commons) in discover_git_dirs(path)? {
        files.push(gd.join("config.worktree"));
        for c in commons {
            files.push(c.join("config"));
            files.push(c.join("shallow"));
        }
    }
    let mut todo: Vec<(PathBuf, usize)> = files.into_iter().map(|f| (f, 0)).collect();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    while let Some((target, depth)) = todo.pop() {
        if depth > 10 || !seen.insert(target.clone()) {
            continue;
        }
        let kind = path_kind(&target);
        if kind == PathKind::Other {
            return Err(format!(
                "git custody: {:?} is not a regular file, and git would block opening it",
                target.display()
            ));
        }
        if kind != PathKind::Regular {
            continue;
        }
        if depth == 0 && target.file_name().and_then(|n| n.to_str()) == Some("shallow") {
            continue;
        }
        if let Some(data) = peek_regular(&target, ATTRIBUTES_FILE_LIMIT) {
            for inc in include_targets(&target, &data) {
                todo.push((inc, depth + 1));
            }
        }
    }
    Ok(())
}

// --- Isolated git custody directory -------------------------------------------------------------

fn trim_trailing_newline(raw: &[u8]) -> &[u8] {
    if raw.ends_with(b"\n") {
        &raw[..raw.len() - 1]
    } else {
        raw
    }
}

fn c_quote_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 2);
    out.push(b'"');
    for &c in raw {
        if (0x20..0x7F).contains(&c) && c != b'"' && c != b'\\' {
            out.push(c);
        } else {
            out.extend_from_slice(format!("\\{:03o}", c).as_bytes());
        }
    }
    out.push(b'"');
    out
}

fn config_quote(value: &str) -> Result<String, String> {
    if value.contains('\n') {
        return Err(format!(
            "git custody: cannot name {value:?} in a config file"
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn copy_regular(src: &Path, dst: &Path) -> Result<(), String> {
    let Some((bytes, meta)) = open_regular_nonblock(src, true, None)? else {
        return Ok(());
    };
    fs::write(dst, bytes)
        .map_err(|e| format!("git custody: failed writing {}: {e}", dst.display()))?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(cpath) = CString::new(os_to_bytes(dst.as_os_str())) {
            let times = [
                libc::timespec {
                    tv_sec: meta.atime(),
                    tv_nsec: meta.atime_nsec(),
                },
                libc::timespec {
                    tv_sec: meta.mtime(),
                    tv_nsec: meta.mtime_nsec(),
                },
            ];
            unsafe {
                libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

fn carried_file(repo: &Path, cwd: Option<&Path>, key: &str) -> Result<Vec<u8>, String> {
    let got = run_git_repo(repo, &["config", "--type=path", "-z", "--get", key], &[])?;
    if got.code == 1 && got.stdout.is_empty() {
        return Ok(Vec::new());
    }
    if got.code != 0 || !got.stdout.ends_with(b"\0") {
        let err = String::from_utf8_lossy(&got.stderr);
        let snippet: String = err.trim().chars().take(200).collect();
        return Err(format!(
            "git custody: cannot read the repository's {key}: {snippet}"
        ));
    }
    let raw_path = &got.stdout[..got.stdout.len() - 1];
    if raw_path.is_empty() {
        return Ok(Vec::new());
    }
    let mut pb = PathBuf::from(bytes_to_os(raw_path));
    if !pb.is_absolute() {
        let Some(base_dir) = cwd else {
            return Err(format!(
                "git custody: {key} {:?} is relative and no work tree says what to",
                pb.display()
            ));
        };
        pb = base_dir.join(pb);
    }
    match open_regular_nonblock(&pb, true, Some(ATTRIBUTES_FILE_LIMIT)) {
        Ok(Some((data, _))) => Ok(data),
        Ok(None) => Ok(Vec::new()),
        Err(exc) => Err(format!(
            "git custody: the repository's {key} cannot be carried as data: {exc}"
        )),
    }
}

pub struct Custody {
    _tmp: TempDir,
    pub git_dir: PathBuf,
    pub work_tree: Option<PathBuf>,
    pub shared_objects_dir: Option<PathBuf>,
    pub pairs: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
}

impl Custody {
    pub fn open(repo: &Path) -> Result<Self, String> {
        Self::open_with(repo, true, false)
    }

    pub fn open_with(repo: &Path, copy_index: bool, shared_objects: bool) -> Result<Self, String> {
        refuse_blocking_files(repo)?;
        let rev_parse = |args: &[&str]| -> Result<Option<OsString>, String> {
            let mut full = vec!["rev-parse"];
            full.extend_from_slice(args);
            let out = run_git_repo(repo, &full, &[])?;
            if out.code == 0 && !out.stdout.is_empty() {
                Ok(Some(bytes_to_os(trim_trailing_newline(&out.stdout))))
            } else {
                Ok(None)
            }
        };

        let gitdir = rev_parse(&["--absolute-git-dir"])?
            .map(PathBuf::from)
            .ok_or_else(|| {
                "git custody: cannot resolve the repository this call names".to_string()
            })?;
        let common = rev_parse(&["--path-format=absolute", "--git-common-dir"])?
            .map(PathBuf::from)
            .ok_or_else(|| {
                "git custody: cannot resolve the repository this call names".to_string()
            })?;
        let format_os = rev_parse(&["--show-object-format"])?.ok_or_else(|| {
            "git custody: cannot resolve the repository this call names".to_string()
        })?;
        let object_format = format_os.to_string_lossy().into_owned();
        if object_format != "sha1" && object_format != "sha256" {
            return Err(format!(
                "git custody: unknown object format {object_format:?}"
            ));
        }
        let top = rev_parse(&["--show-toplevel"])?.map(PathBuf::from);
        let head = rev_parse(&["--verify", "-q", "HEAD^{commit}"])?
            .map(|s| s.to_string_lossy().into_owned());

        // Check extensions.*
        let ext = run_git_repo(
            repo,
            &["config", "-z", "--get-regexp", r"^extensions\."],
            &[],
        )?;
        if ext.code != 0 && ext.code != 1 {
            let err = String::from_utf8_lossy(&ext.stderr);
            let snippet: String = err.trim().chars().take(200).collect();
            return Err(format!(
                "git custody: cannot read the repository's extensions: {snippet}"
            ));
        }
        for rec in ext.stdout.split(|&b| b == 0) {
            if rec.is_empty() {
                continue;
            }
            let key = rec.split(|&b| b == b'\n').next().unwrap_or(rec);
            let name = key
                .splitn(2, |&b| b == b'.')
                .nth(1)
                .map(|b| String::from_utf8_lossy(b).to_ascii_lowercase())
                .unwrap_or_default();
            if !HONOURABLE_EXTENSIONS.contains(&name.as_str()) {
                return Err(format!(
                    "git custody: the repository declares extensions.{name}, which the custody git dir cannot honour"
                ));
            }
        }

        // Refuse partial clones (promisor / partialclonefilter)
        let promisor = run_git_repo(
            repo,
            &[
                "config",
                "-z",
                "--get-regexp",
                r"^remote\..*\.(promisor|partialclonefilter)$",
            ],
            &[],
        )?;
        if promisor.code != 0 && promisor.code != 1 {
            let err = String::from_utf8_lossy(&promisor.stderr);
            let snippet: String = err.trim().chars().take(200).collect();
            return Err(format!(
                "git custody: cannot read the repository's remotes: {snippet}"
            ));
        }
        for rec in promisor.stdout.split(|&b| b == 0) {
            if rec.is_empty() {
                continue;
            }
            let mut parts = rec.splitn(2, |&b| b == b'\n');
            let key = parts.next().unwrap_or(&[]);
            let val = parts.next().unwrap_or(&[]);
            let key_s = String::from_utf8_lossy(key);
            let val_low = String::from_utf8_lossy(val).trim().to_ascii_lowercase();
            if !key.is_empty()
                && (key_s.to_ascii_lowercase().ends_with(".partialclonefilter")
                    || !matches!(val_low.as_str(), "false" | "no" | "off" | "0"))
            {
                return Err(format!(
                    "git custody: the repository is a partial clone ({key_s}): the custody cannot read the objects it never fetched"
                ));
            }
        }

        // Data-only core.* settings
        let mut pairs = Vec::new();
        for key in CUSTODY_CORE_KEYS {
            let full_key = format!("core.{key}");
            let got = run_git_repo(repo, &["config", "-z", "--get", &full_key], &[])?;
            if got.code == 0 && !got.stdout.is_empty() {
                let val_bytes = got.stdout.split(|&b| b == 0).next().unwrap_or(&[]);
                pairs.push((OsString::from(full_key), bytes_to_os(val_bytes)));
            }
        }

        let work_cwd = top.as_deref().or(Some(repo));
        let attributes = carried_file(repo, work_cwd, "core.attributesFile")?;
        let excludes = carried_file(repo, work_cwd, "core.excludesFile")?;

        let tmp = tempfile::Builder::new()
            .prefix("open-fleet-git-custody-")
            .tempdir()
            .map_err(|e| format!("git custody: tempdir failed: {e}"))?;
        let root = tmp.path().to_path_buf();
        for sub in ["refs/heads", "refs/tags", "info"] {
            fs::create_dir_all(root.join(sub))
                .map_err(|e| format!("git custody: mkdir {sub} failed: {e}"))?;
        }

        let repo_fmt_ver = if object_format == "sha1" { 0 } else { 1 };
        let mut cfg =
            format!("[core]\n\trepositoryformatversion = {repo_fmt_ver}\n\tbare = true\n");
        for (key, fname, content) in [
            ("attributesFile", "attributes", &attributes),
            ("excludesFile", "excludes", &excludes),
        ] {
            let target_path = root.join(fname);
            fs::write(&target_path, content)
                .map_err(|e| format!("git custody: write {fname} failed: {e}"))?;
            let q = config_quote(&target_path.to_string_lossy())?;
            cfg.push_str(&format!("\t{key} = {q}\n"));
        }
        if object_format != "sha1" {
            cfg.push_str(&format!("[extensions]\n\tobjectformat = {object_format}\n"));
        }
        fs::write(root.join("config"), cfg)
            .map_err(|e| format!("git custody: write config failed: {e}"))?;

        let head_content = match head {
            Some(h) => format!("{h}\n"),
            None => "ref: refs/heads/open-fleet-unborn\n".to_string(),
        };
        fs::write(root.join("HEAD"), head_content)
            .map_err(|e| format!("git custody: write HEAD failed: {e}"))?;

        let common_objects = common.join("objects");
        let shared_objects_dir = if shared_objects {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&common_objects, root.join("objects"))
                    .map_err(|e| format!("git custody: symlink objects failed: {e}"))?;
                None
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(root.join("objects"))
                    .map_err(|e| format!("git custody: mkdir objects failed: {e}"))?;
                Some(common_objects)
            }
        } else {
            fs::create_dir_all(root.join("objects/info"))
                .map_err(|e| format!("git custody: mkdir objects/info failed: {e}"))?;
            let mut alt_line = c_quote_bytes(&os_to_bytes(common_objects.as_os_str()));
            alt_line.push(b'\n');
            fs::write(root.join("objects/info/alternates"), alt_line)
                .map_err(|e| format!("git custody: write alternates failed: {e}"))?;
            None
        };

        copy_regular(&common.join("info/exclude"), &root.join("info/exclude"))?;
        copy_regular(
            &common.join("info/attributes"),
            &root.join("info/attributes"),
        )?;
        copy_regular(&common.join("shallow"), &root.join("shallow"))?;
        if copy_index {
            copy_regular(&gitdir.join("index"), &root.join("index"))?;
            copy_regular(
                &gitdir.join("info/sparse-checkout"),
                &root.join("info/sparse-checkout"),
            )?;
            if let Ok(entries) = fs::read_dir(&gitdir) {
                let mut shared: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.starts_with("sharedindex."))
                    .collect();
                shared.sort();
                for name in shared {
                    copy_regular(&gitdir.join(&name), &root.join(&name))?;
                }
            }
        }
        Ok(Self {
            _tmp: tmp,
            git_dir: root,
            work_tree: top,
            shared_objects_dir,
            pairs,
            cwd: repo.to_path_buf(),
        })
    }

    pub fn lead(&self) -> Vec<OsString> {
        let mut v = vec![
            OsString::from("-C"),
            self.cwd.as_os_str().to_os_string(),
            OsString::from("--git-dir"),
            self.git_dir.as_os_str().to_os_string(),
        ];
        if let Some(wt) = &self.work_tree {
            v.push(OsString::from("--work-tree"));
            v.push(wt.as_os_str().to_os_string());
        }
        v
    }

    pub fn run(
        &self,
        args: &[OsString],
        extra_blanks: &[(OsString, OsString)],
    ) -> Result<GitOutput, String> {
        let mut all_blanks = self.pairs.clone();
        all_blanks.extend(extra_blanks.iter().cloned());
        if let Some(obj_dir) = &self.shared_objects_dir {
            let git = git_binary()?;
            let mut cmd = Command::new(git);
            cmd.args(self.lead())
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_clear()
                .envs(custody_env(&all_blanks))
                .env("GIT_OBJECT_DIRECTORY", obj_dir);
            let out = cmd
                .output()
                .map_err(|err| format!("git failed to run: {err}"))?;
            Ok(GitOutput {
                code: out.status.code().unwrap_or(1),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        } else {
            run_git_raw(&self.lead(), args, &all_blanks)
        }
    }
}
