//! Verification authority pinning, custody classification, scrubbed subprocess execution,
//! `#750 C19` proof-command grammar, and test-runner oracle path discovery —
//! native Rust port of `verify.py`'s `_Authority`, `_command_oracle_paths`, and `_is_oracle_path`.

use crate::diff_scope::{fnmatchcase, is_test_path};
use crate::verify::diff::{extract_diff, is_hex40, shlex_split};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub const SOUND_PROVENANCE: &[&str] = &["ci", "mcp", "sdk", "dispatch"];
pub const INDEPENDENT_REVIEWER_ASSOCIATIONS: &[&str] = &["OWNER", "MEMBER", "COLLABORATOR"];
pub const ABSENT_GH: &str = "gh absent at startup (the review authority is pinned once, before the control, and never re-resolved — h409 F-1)";
pub const ABSENT_GIT: &str =
    "git absent at startup (pinned once, before the control, never re-resolved — h409 R2)";

const GH_ENV_KEEP: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "GH_TOKEN",
    "GITHUB_TOKEN",
];

const AMBIENT_KEEP: &[&str] = &["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "NO_COLOR"];

pub const SCRUB_NOTE: &str = " (gh ran under a scrubbed environment: XDG_CONFIG_HOME, HTTPS_PROXY/NO_PROXY and SSL_CERT_FILE are dropped with every other steering variable — only PATH, HOME, TMPDIR, TMP, TEMP, GH_TOKEN, GITHUB_TOKEN pass; h409 R3)";

const CUSTODY_FLOOR: &[(&str, &str)] = &[
    ("core.alternateRefsCommand", "exit 0"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("status.submoduleSummary", "false"),
    ("log.showSignature", "false"),
    ("gpg.program", "/dev/null"),
    ("gpg.openpgp.program", "/dev/null"),
    ("gpg.x509.program", "/dev/null"),
    ("gpg.ssh.program", "/dev/null"),
    ("maintenance.auto", "false"),
    ("gc.auto", "0"),
];

const SHELL_NAMES: &[&str] = &[
    "sh", "bash", "rbash", "dash", "zsh", "rzsh", "ksh", "rksh", "ash", "hush", "csh", "tcsh",
];

const SAFE_SHELL_O_OPTIONS: &[&str] = &[
    "allexport",
    "braceexpand",
    "errexit",
    "errtrace",
    "functrace",
    "hashall",
    "histexpand",
    "monitor",
    "noclobber",
    "noexec",
    "noglob",
    "notify",
    "nounset",
    "physical",
    "pipefail",
    "posix",
    "verbose",
    "xtrace",
];

const NC_FORBID_ENV_VARS: &[&str] = &[
    "PATH",
    "IFS",
    "CDPATH",
    "ENV",
    "BASH_ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "BASH_LOADABLES_PATH",
    "BASH_COMPAT",
    "POSIXLY_CORRECT",
    "ZDOTDIR",
    "FPATH",
    "GLOBIGNORE",
    "EXECIGNORE",
    "PROMPT_COMMAND",
    "PS0",
    "PS4",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "GLIBC_TUNABLES",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONSAFEPATH",
    "PYTHONPYCACHEPREFIX",
    "PYTHONWARNINGS",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "VIRTUAL_ENV",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "DENO_DIR",
    "BUN_INSTALL",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "GEM_HOME",
    "GEM_PATH",
    "BUNDLE_GEMFILE",
    "AWKPATH",
    "AWKLIBPATH",
    "PHPRC",
    "PHP_INI_SCAN_DIR",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "R_LIBS",
    "R_LIBS_USER",
    "R_LIBS_SITE",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CONFIG_HOME",
    "GH_CONFIG_DIR",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
];

const NC_FORBID_ENV_PREFIXES: &[&str] = &[
    "GIT_",
    "ORCA_",
    "OPEN_FLEET_",
    "GH_",
    "GITHUB_",
    "LD_",
    "DYLD_",
    "LUA_",
    "BASH_FUNC_",
    "PYTHON",
    "NODE_",
    "PERL",
    "RUBY",
    "GEM_",
    "BUNDLE_",
    "DENO_",
    "BUN_",
    "AWK",
    "PHP",
    "R_",
];

const NC_FORBID_MUX_EXES: &[&str] = &[
    "busybox",
    "toybox",
    "sbase-box",
    "ubase-box",
    "xargs",
    "gxargs",
    "find",
    "gfind",
    "stdbuf",
    "setsid",
    "flock",
    "chrt",
    "ionice",
    "taskset",
    "prlimit",
    "choom",
    "uclampset",
    "numactl",
    "eatmydata",
    "chronic",
    "script",
    "expect",
    "screen",
    "tmux",
    "ssh",
    "su",
    "sudo",
    "doas",
    "pkexec",
    "runuser",
    "dzdo",
    "pfexec",
    "chroot",
    "arch-chroot",
    "fakeroot",
    "fakechroot",
    "nsenter",
    "unshare",
    "bwrap",
    "firejail",
    "proot",
    "time",
    "parallel",
    "watch",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "perf",
    "valgrind",
    "torsocks",
    "tsocks",
    "proxychains",
    "proxychains4",
    "catchsegv",
    "fish",
    "elvish",
    "nu",
    "nushell",
    "xonsh",
    "pwsh",
    "powershell",
    "rc",
    "es",
    "sed",
    "gsed",
    "ssed",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "bawk",
    "deno",
    "bun",
    "rg",
    "ripgrep",
    "ag",
    "ack",
    "fd",
    "fdfind",
    "fzf",
    "ugrep",
    "ug",
    "tar",
    "gtar",
    "bsdtar",
    "sort",
    "gsort",
    "split",
    "gsplit",
    "m4",
    "gm4",
];

// Standard Python 3.11-3.13 stdlib & builtin module names (minus `unittest`) plus common packaging/eval tools.
const FORBID_PY_MODS: &[&str] = &[
    "__future__",
    "__main__",
    "_abc",
    "_aix_support",
    "_android_support",
    "_apple_support",
    "_ast",
    "_asyncio",
    "_bisect",
    "_blake2",
    "_bootsubprocess",
    "_bz2",
    "_codecs",
    "_codecs_cn",
    "_codecs_hk",
    "_codecs_iso2022",
    "_codecs_jp",
    "_codecs_kr",
    "_codecs_tw",
    "_collections",
    "_collections_abc",
    "_colorize",
    "_compat_pickle",
    "_compression",
    "_contextvars",
    "_crypt",
    "_csv",
    "_ctypes",
    "_curses",
    "_curses_panel",
    "_datetime",
    "_dbm",
    "_decimal",
    "_elementtree",
    "_frozen_importlib",
    "_frozen_importlib_external",
    "_functools",
    "_gdbm",
    "_hashlib",
    "_heapq",
    "_imp",
    "_interpchannels",
    "_interpqueues",
    "_interpreters",
    "_io",
    "_ios_support",
    "_json",
    "_locale",
    "_lsprof",
    "_lzma",
    "_markupbase",
    "_md5",
    "_msi",
    "_multibytecodec",
    "_multiprocessing",
    "_opcode",
    "_opcode_metadata",
    "_operator",
    "_osx_support",
    "_overlapped",
    "_pickle",
    "_posixshmem",
    "_posixsubprocess",
    "_py_abc",
    "_pydatetime",
    "_pydecimal",
    "_pyio",
    "_pylong",
    "_pyrepl",
    "_queue",
    "_random",
    "_scproxy",
    "_sha1",
    "_sha2",
    "_sha256",
    "_sha3",
    "_sha512",
    "_signal",
    "_sitebuiltins",
    "_socket",
    "_sqlite3",
    "_sre",
    "_ssl",
    "_stat",
    "_statistics",
    "_string",
    "_strptime",
    "_struct",
    "_suggestions",
    "_symtable",
    "_sysconfig",
    "_thread",
    "_threading_local",
    "_tkinter",
    "_tokenize",
    "_tracemalloc",
    "_typing",
    "_uuid",
    "_warnings",
    "_weakref",
    "_weakrefset",
    "_winapi",
    "_wmi",
    "_zoneinfo",
    "abc",
    "aifc",
    "antigravity",
    "argparse",
    "array",
    "ast",
    "asynchat",
    "asyncio",
    "asyncore",
    "atexit",
    "audioop",
    "base64",
    "bdb",
    "binascii",
    "binhex",
    "bisect",
    "builtins",
    "bz2",
    "cProfile",
    "calendar",
    "cgi",
    "cgitb",
    "chunk",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "compileall",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "coverage",
    "crypt",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "distutils",
    "doctest",
    "email",
    "encodings",
    "ensurepip",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "genericpath",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "idlelib",
    "imaplib",
    "imghdr",
    "imp",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "ipython",
    "IPython",
    "itertools",
    "json",
    "keyword",
    "lib2to3",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "mailcap",
    "marshal",
    "math",
    "mimetypes",
    "mmap",
    "modulefinder",
    "msilib",
    "msvcrt",
    "multiprocessing",
    "netrc",
    "nis",
    "nntplib",
    "nox",
    "nt",
    "ntpath",
    "nturl2path",
    "numbers",
    "opcode",
    "operator",
    "optparse",
    "os",
    "ossaudiodev",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pip",
    "pipes",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posix",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "pydoc_data",
    "pyexpat",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "setuptools",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtpd",
    "smtplib",
    "sndhdr",
    "socket",
    "socketserver",
    "spwd",
    "sqlite3",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "sunau",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "telnetlib",
    "tempfile",
    "termios",
    "test",
    "textwrap",
    "this",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "tox",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "urllib",
    "uu",
    "uuid",
    "venv",
    "virtualenv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "wheel",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

fn shell_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:sh|bash|rbash|dash|zsh|rzsh|ksh|rksh|mksh|pdksh|yash|posh|ash|hush|csh|tcsh)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex")
    })
}

fn non_posix_shell_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:csh|tcsh|r?zsh)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex")
    })
}

fn csh_tcsh_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:csh|tcsh)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex"))
}

fn rzsh_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^r?zsh(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex"))
}

fn multicall_box_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:busybox|toybox|sbase-box|ubase-box)(?:[.-][A-Za-z0-9_.-]+)?$")
            .expect("regex")
    })
}

fn mux_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(?:(?:g?sed|gnused|[gmn]?awk|deno|bun)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?",
            r"|(?:busybox|toybox|sbase-box|ubase-box)(?:[.-][A-Za-z0-9_.-]+)?",
            r"|ld\.so(?:\.[0-9]+)?|ld-linux[A-Za-z0-9_.-]*|ld-musl[A-Za-z0-9_.-]*",
            r"|proxychains[0-9]*)$",
        ))
        .expect("regex")
    })
}

fn python_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:python|pypy)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex"))
}

fn other_interp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:node(?:js)?|ruby|perl|php|lua(?:jit)?|Rscript)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$",
        )
        .expect("regex")
    })
}

fn make_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^g?make(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex"))
}

fn pytest_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:pytest|py\.test)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex")
    })
}

fn grep_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[efg]?grep)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$").expect("regex"))
}

fn dotted_ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$").expect("regex")
    })
}

fn hex40_or_64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$").expect("regex"))
}

fn js_test_config_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:^|/)(?:jest|vitest|playwright|cypress|karma)\.config\.").expect("regex")
    })
}

fn filter_key_re() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::bytes::Regex::new(r"(?-u)(?s)\Afilter\.(.+)\.[^.]+\z").expect("regex"))
}

fn diff_cmd_key_re() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(r"(?-u)(?s)\Adiff\.(?:.+)\.(?:textconv|command)\z").expect("regex")
    })
}

fn merge_key_re() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::bytes::Regex::new(r"(?-u)(?s)\Amerge\.(.+)\.[^.]+\z").expect("regex"))
}

pub fn devnull() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn path_to_posix(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.into_owned()
    }
}

/// Normalize path lexically like Python `os.path.normpath`.
pub fn normpath_str(raw: &str) -> String {
    if raw.is_empty() {
        return ".".to_string();
    }
    let abs = raw.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if let Some(&top) = stack.last() {
                if top != ".." {
                    stack.pop();
                    continue;
                }
            }
            if !abs {
                stack.push("..");
            }
        } else {
            stack.push(part);
        }
    }
    let joined = stack.join("/");
    if abs {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Pure Path(p).as_posix() normalization matching Python's `pathlib.Path(s).as_posix()`.
pub fn pathlib_posix(raw: &str) -> String {
    if raw.is_empty() {
        return ".".to_string();
    }
    let abs = raw.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        parts.push(seg);
    }
    if abs {
        format!("/{}", parts.join("/"))
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

pub fn which_in(binary: &str, search_path: Option<&str>) -> Option<PathBuf> {
    if binary.is_empty() {
        return None;
    }
    let is_exec = |p: &Path| -> bool {
        let Ok(meta) = fs::metadata(p) else {
            return false;
        };
        if !meta.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            (meta.permissions().mode() & 0o111) != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    if binary.contains('/') || (cfg!(windows) && binary.contains('\\')) {
        let p = PathBuf::from(binary);
        return if is_exec(&p) { Some(p) } else { None };
    }
    let path_os: OsString = match search_path {
        Some(p) => OsString::from(p),
        None => env::var_os("PATH")?,
    };
    for dir in env::split_paths(&path_os) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(binary);
        if is_exec(&cand) {
            return Some(cand);
        }
        #[cfg(windows)]
        {
            for ext in &[".exe", ".cmd", ".bat"] {
                let c2 = dir.join(format!("{binary}{ext}"));
                if is_exec(&c2) {
                    return Some(c2);
                }
            }
        }
    }
    None
}

pub fn abspath(p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn run_proc_bytes(
    prog: &Path,
    args: &[OsString],
    cwd: Option<&Path>,
    env_map: &[(OsString, OsString)],
    stdin_bytes: Option<&[u8]>,
    timeout_s: u64,
) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    cmd.env_clear();
    for (k, v) in env_map {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (124, Vec::new(), e.to_string()),
    };

    let mut stdin_handle = None;
    if let Some(payload) = stdin_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            let owned = payload.to_vec();
            stdin_handle = Some(thread::spawn(move || {
                let _ = stdin.write_all(&owned);
            }));
        }
    }

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_t = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(ref mut r) = out_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_t = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(ref mut r) = err_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                break None;
            }
        }
    };
    if let Some(h) = stdin_handle {
        let _ = h.join();
    }
    let out_bytes = out_t.join().unwrap_or_default();
    let err_bytes = err_t.join().unwrap_or_default();
    let err_text = String::from_utf8_lossy(&err_bytes).into_owned();
    match status {
        Some(st) => (st.code().unwrap_or(1), out_bytes, err_text),
        None => (
            124,
            out_bytes,
            format!("Command timed out after {timeout_s} seconds"),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopSig {
    pub path: String,
    pub mode_fmt: u32,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecFileRec {
    pub abs_path: String,
    pub real_path: String,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub digest: String,
    pub hops: Vec<HopSig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedExecRec {
    pub argv_idx: usize,
    pub tok: String,
    pub self_rec: ExecFileRec,
    pub sub_chain: Vec<ExecFileRec>,
}

#[derive(Debug, Clone)]
pub struct DiscoveryMatcher {
    pub exact: HashSet<String>,
    pub py_roots: Vec<String>,
    pub py_globs: Vec<String>,
    pub ut_roots: Vec<String>,
    pub ut_globs: Vec<String>,
    pub regexes: Vec<Regex>,
}

impl DiscoveryMatcher {
    pub fn matches(&self, p: &str) -> bool {
        if self.exact.contains(p) {
            return true;
        }
        let under = |path: &str, tops: &[String]| -> bool {
            let parts: Vec<&str> = path.split('/').collect();
            let ancs: Vec<String> = (1..parts.len()).map(|k| parts[..k].join("/")).collect();
            tops.iter()
                .any(|t| t.is_empty() || path == t || ancs.iter().any(|a| fnmatchcase(a, t)))
        };
        let collected = |path: &str, globs: &[String]| -> bool {
            let leaf = path.rsplit('/').next().unwrap_or(path);
            globs.iter().any(|g| {
                if g.contains('/') {
                    fnmatchcase(path, g) || fnmatchcase(path, &format!("*/{g}"))
                } else {
                    fnmatchcase(leaf, g)
                }
            })
        };
        if p.ends_with(".py") {
            if !self.py_globs.is_empty() && under(p, &self.py_roots) && collected(p, &self.py_globs)
            {
                return true;
            }
            if !self.ut_globs.is_empty() && under(p, &self.ut_roots) && collected(p, &self.ut_globs)
            {
                return true;
            }
        }
        let slash = format!("/{p}");
        self.regexes.iter().any(|r| r.is_match(&slash))
    }
}

pub struct ControlGitDir {
    pub _tmp: TempDir,
    pub path: PathBuf,
}

pub struct VerifyCtx {
    pub roots_git: Option<PathBuf>,
    pub roots_evidence: Option<PathBuf>,
    pub git_bin: Option<PathBuf>,
    pub git_custody: Option<String>,
    pub gh_bin: Option<PathBuf>,
    pub gh_custody: Option<String>,
    pub gitleaks_bin: Option<PathBuf>,
    pub gitleaks_custody: Option<String>,
    pub lane: Option<String>,
    pub repo_source: Option<String>,
    pub split_cache: Option<bool>,
    pub discovery_cache: HashMap<(String, Option<String>), Result<DiscoveryMatcher, String>>,
}

impl Default for VerifyCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyCtx {
    pub fn new() -> Self {
        Self {
            roots_git: None,
            roots_evidence: None,
            git_bin: None,
            git_custody: None,
            gh_bin: None,
            gh_custody: None,
            gitleaks_bin: None,
            gitleaks_custody: None,
            lane: None,
            repo_source: None,
            split_cache: None,
            discovery_cache: HashMap::new(),
        }
    }

    pub fn pin_git(&mut self) {
        if let Some(found) = which_in("git", None) {
            let abs = abspath(&found);
            let cls = self.classify(&abs);
            self.git_bin = Some(abs);
            self.git_custody = Some(cls);
        } else {
            self.git_bin = None;
            self.git_custody = Some("absent".to_string());
        }
    }

    pub fn pin_gitleaks(&mut self) {
        if let Some(found) = which_in("gitleaks", None) {
            let abs = abspath(&found);
            let cls = self.classify(&abs);
            self.gitleaks_bin = Some(abs);
            self.gitleaks_custody = Some(cls);
        } else {
            self.gitleaks_bin = None;
            self.gitleaks_custody = Some("absent".to_string());
        }
    }

    pub fn resolve(
        &mut self,
        provenance: Option<&str>,
        enforcement: bool,
        explicit_repo: Option<&str>,
    ) -> Option<String> {
        self.lane = if let Some(p) = provenance {
            if SOUND_PROVENANCE.contains(&p) {
                Some(format!("provenance={p}"))
            } else if enforcement {
                Some("enforcement (signed dispatch record + pubkey)".to_string())
            } else {
                None
            }
        } else if enforcement {
            Some("enforcement (signed dispatch record + pubkey)".to_string())
        } else {
            None
        };
        self.pin_git();
        if let Some(found) = which_in("gh", None) {
            let abs = abspath(&found);
            let cls = self.classify(&abs);
            self.gh_bin = Some(abs);
            self.gh_custody = Some(cls);
        } else {
            self.gh_bin = None;
            self.gh_custody = Some("absent".to_string());
        }
        self.pin_gitleaks();
        if let Some(r) = explicit_repo {
            if !r.is_empty() {
                self.repo_source = Some("explicit".to_string());
                return Some(r.to_string());
            }
        }
        let inferred = self.infer_repo();
        self.repo_source = inferred.as_ref().map(|_| "inferred".to_string());
        inferred
    }

    pub fn nc_env(&self) -> Vec<(OsString, OsString)> {
        let mut out = Vec::new();
        let mut has_path = false;
        for (k, v) in env::vars_os() {
            let ks = k.to_string_lossy();
            if AMBIENT_KEEP.contains(&ks.as_ref()) || ks.starts_with("LC_") {
                if ks == "PATH" {
                    has_path = true;
                    let filtered: Vec<PathBuf> = env::split_paths(&v)
                        .filter(|p| !p.as_os_str().is_empty() && p.is_absolute())
                        .collect();
                    if let Ok(joined) = env::join_paths(filtered) {
                        out.push((k, joined));
                    }
                } else if ks != "NO_COLOR" {
                    out.push((k, v));
                }
            }
        }
        let _ = has_path;
        out.push((OsString::from("NO_COLOR"), OsString::from("1")));
        out
    }

    pub fn gh_env(&self) -> Vec<(OsString, OsString)> {
        let mut out = Vec::new();
        for &k in GH_ENV_KEEP {
            if let Some(v) = env::var_os(k) {
                out.push((OsString::from(k), v));
            }
        }
        out
    }

    pub fn git_env(&self) -> Vec<(OsString, OsString)> {
        let dn = devnull();
        let mut pairs: Vec<(&str, &str)> = vec![
            ("core.fsmonitor", "false"),
            ("protocol.ext.allow", "never"),
            ("safe.directory", "*"),
            ("core.hooksPath", dn),
            ("diff.external", ""),
        ];
        for &(k, v) in CUSTODY_FLOOR {
            pairs.push((k, if v == "/dev/null" { dn } else { v }));
        }
        let mut env_vec = self.nc_env();
        let extras = [
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_GRAFT_FILE", dn),
            ("GIT_CONFIG_GLOBAL", dn),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_ALLOW_PROTOCOL", "file"),
            ("GIT_ATTR_NOSYSTEM", "1"),
        ];
        for (k, v) in extras {
            env_vec.push((OsString::from(k), OsString::from(v)));
        }
        env_vec.push((
            OsString::from("GIT_CONFIG_COUNT"),
            OsString::from(pairs.len().to_string()),
        ));
        for (i, (k, v)) in pairs.iter().enumerate() {
            env_vec.push((
                OsString::from(format!("GIT_CONFIG_KEY_{i}")),
                OsString::from(k),
            ));
            env_vec.push((
                OsString::from(format!("GIT_CONFIG_VALUE_{i}")),
                OsString::from(v),
            ));
        }
        env_vec
    }

    pub fn blanked_env(&self, blanks: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
        let mut env_vec = self.git_env();
        let first: usize = env_vec
            .iter()
            .find(|(k, _)| k == "GIT_CONFIG_COUNT")
            .and_then(|(_, v)| v.to_string_lossy().parse::<usize>().ok())
            .unwrap_or(0);
        for (idx, (k, v)) in blanks.iter().enumerate() {
            let n = first + idx;
            env_vec.push((OsString::from(format!("GIT_CONFIG_KEY_{n}")), k.clone()));
            env_vec.push((OsString::from(format!("GIT_CONFIG_VALUE_{n}")), v.clone()));
        }
        for (k, v) in &mut env_vec {
            if k == "GIT_CONFIG_COUNT" {
                *v = OsString::from((first + blanks.len()).to_string());
                break;
            }
        }
        env_vec
    }

    pub fn driver_blanks(&self, repo: &Path) -> Result<Vec<(OsString, OsString)>, String> {
        let Some(git) = self.git_bin.as_deref() else {
            return Err(ABSENT_GIT.to_string());
        };
        let args = vec![
            OsString::from("-C"),
            repo.as_os_str().to_os_string(),
            OsString::from("config"),
            OsString::from("--list"),
            OsString::from("-z"),
            OsString::from("--name-only"),
        ];
        let (code, out, err) = run_proc_bytes(git, &args, None, &self.git_env(), None, 20);
        if code != 0 {
            let snippet: String = err.trim().chars().take(200).collect();
            return Err(format!("git config --list exited {code}: {snippet}"));
        }
        if !out.is_empty() && !out.ends_with(&[0]) {
            return Err(
                "git config --list printed output that is not NUL-terminated keys".to_string(),
            );
        }
        let keys: Vec<&[u8]> = if out.is_empty() {
            Vec::new()
        } else {
            let mut parts: Vec<&[u8]> = out.split(|&b| b == 0).collect();
            parts.pop();
            parts
        };
        if keys.iter().any(|k| k.is_empty()) {
            return Err("git config --list printed an empty key".to_string());
        }
        let mut pairs: Vec<(OsString, OsString)> = Vec::new();
        let mut filt_seen: HashSet<Vec<u8>> = HashSet::new();
        let mut merge_seen: HashSet<Vec<u8>> = HashSet::new();
        let bytes_to_os = |b: &[u8]| -> OsString {
            #[cfg(unix)]
            {
                OsString::from_vec(b.to_vec())
            }
            #[cfg(not(unix))]
            {
                OsString::from(String::from_utf8_lossy(b).into_owned())
            }
        };
        for key in keys {
            if let Some(caps) = filter_key_re().captures(key) {
                let drv = caps.get(1).expect("g1").as_bytes().to_vec();
                if filt_seen.insert(drv.clone()) {
                    for (var, val) in [
                        (&b"clean"[..], ""),
                        (&b"smudge"[..], ""),
                        (&b"process"[..], ""),
                        (&b"required"[..], "false"),
                    ] {
                        let mut k = b"filter.".to_vec();
                        k.extend_from_slice(&drv);
                        k.push(b'.');
                        k.extend_from_slice(var);
                        pairs.push((bytes_to_os(&k), OsString::from(val)));
                    }
                }
            } else if let Some(caps) = merge_key_re().captures(key) {
                let drv = caps.get(1).expect("g1").as_bytes().to_vec();
                if merge_seen.insert(drv.clone()) {
                    let mut k = b"merge.".to_vec();
                    k.extend_from_slice(&drv);
                    k.extend_from_slice(b".driver");
                    pairs.push((bytes_to_os(&k), OsString::from("exit 1")));
                }
            } else if diff_cmd_key_re().is_match(key) {
                pairs.push((bytes_to_os(key), OsString::from("")));
            }
        }
        Ok(pairs)
    }

    pub fn control_git_dir(&self, top: &Path, head: &str) -> Result<ControlGitDir, String> {
        of_common::gitexec::refuse_blocking_files(top)?;
        let Some(git) = self.git_bin.as_deref() else {
            return Err(ABSENT_GIT.to_string());
        };
        let env_vec = self.git_env();
        let run_g = |extra: &[&str]| -> (i32, Vec<u8>, String) {
            let mut argv = vec![OsString::from("-C"), top.as_os_str().to_os_string()];
            for a in extra {
                argv.push(OsString::from(a));
            }
            run_proc_bytes(git, &argv, None, &env_vec, None, 30)
        };
        let (c1, common_b, e1) =
            run_g(&["rev-parse", "--path-format=absolute", "--git-common-dir"]);
        let (c2, fmt_b, e2) = run_g(&["rev-parse", "--show-object-format"]);
        let common_s = String::from_utf8_lossy(&common_b)
            .trim_end_matches('\n')
            .to_string();
        let fmt_s = String::from_utf8_lossy(&fmt_b).trim().to_string();
        if c1 != 0 || c2 != 0 || common_s.is_empty() {
            let err = if !e1.trim().is_empty() { e1 } else { e2 };
            return Err(format!(
                "cannot locate the source repository's object store: {}",
                err.trim()
            ));
        }
        // Check extensions and partial clones
        let (ce, ext_b, ee) = run_g(&["config", "-z", "--get-regexp", r"^extensions\."]);
        if ce != 0 && ce != 1 {
            return Err(format!(
                "git custody: cannot read the repository's extensions: {}",
                ee.trim()
            ));
        }
        for rec in ext_b.split(|&b| b == 0) {
            if rec.is_empty() {
                continue;
            }
            let key = rec.split(|&b| b == b'\n').next().unwrap_or(rec);
            let name = key
                .splitn(2, |&b| b == b'.')
                .nth(1)
                .map(|b| String::from_utf8_lossy(b).to_ascii_lowercase())
                .unwrap_or_default();
            if name != "objectformat" && name != "worktreeconfig" {
                return Err(format!(
                    "git custody: the repository declares extensions.{name}, which the custody git dir cannot honour"
                ));
            }
        }
        // Carry core.attributesFile as data if present
        let (ca, attr_path_b, _) = run_g(&["config", "-z", "--get", "core.attributesFile"]);
        let mut attr_data = Vec::new();
        if ca == 0 && !attr_path_b.is_empty() {
            let p_raw = attr_path_b.split(|&b| b == 0).next().unwrap_or(&[]);
            let p_str = String::from_utf8_lossy(p_raw).into_owned();
            if !p_str.is_empty() {
                let target = if Path::new(&p_str).is_absolute() {
                    PathBuf::from(&p_str)
                } else {
                    top.join(&p_str)
                };
                if let Ok(meta) = fs::symlink_metadata(&target) {
                    if !meta.file_type().is_file() {
                        return Err(format!(
                            "git custody: core.attributesFile {p_str:?} is not a regular file"
                        ));
                    }
                    attr_data = fs::read(&target).map_err(|e| {
                        format!("git custody: cannot read core.attributesFile {p_str:?}: {e}")
                    })?;
                }
            }
        }

        let tmp = tempfile::Builder::new()
            .prefix("open-fleet-ctrl-git-")
            .tempdir()
            .map_err(|e| format!("tempdir failed: {e}"))?;
        let gd = tmp.path().to_path_buf();
        for sub in ["refs/heads", "refs/tags", "info"] {
            fs::create_dir_all(gd.join(sub)).map_err(|e| e.to_string())?;
        }
        let repo_fmt_ver = if fmt_s == "sha1" { 0 } else { 1 };
        let attr_file = gd.join("attributes");
        fs::write(&attr_file, &attr_data).map_err(|e| e.to_string())?;
        let mut cfg = format!(
            "[core]\n\trepositoryformatversion = {repo_fmt_ver}\n\tbare = false\n\tattributesFile = \"{}\"\n",
            attr_file.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
        );
        if fmt_s != "sha1" {
            cfg.push_str(&format!("[extensions]\n\tobjectformat = {fmt_s}\n"));
        }
        fs::write(gd.join("config"), cfg).map_err(|e| e.to_string())?;
        fs::write(gd.join("HEAD"), format!("{head}\n")).map_err(|e| e.to_string())?;

        let common_path = PathBuf::from(&common_s);
        let src_objects = common_path.join("objects");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&src_objects, gd.join("objects"))
                .map_err(|e| format!("symlink objects failed: {e}"))?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(gd.join("objects/info")).map_err(|e| e.to_string())?;
            fs::write(
                gd.join("objects/info/alternates"),
                format!("{}\n", src_objects.to_string_lossy()),
            )
            .map_err(|e| e.to_string())?;
        }
        for name in ["info/exclude", "info/attributes", "shallow"] {
            let src = common_path.join(name);
            if let Ok(meta) = fs::symlink_metadata(&src) {
                if !meta.file_type().is_file() {
                    return Err(format!("git custody: {name} is not a regular file"));
                }
                let bytes = fs::read(&src).map_err(|e| format!("git custody: read {name}: {e}"))?;
                fs::write(gd.join(name), bytes).map_err(|e| e.to_string())?;
            }
        }
        Ok(ControlGitDir {
            _tmp: tmp,
            path: gd,
        })
    }

    pub fn git_bytes(&self, args: &[&str], timeout_s: u64) -> (i32, Vec<u8>, String) {
        let Some(git) = self.git_bin.as_deref() else {
            return (1, Vec::new(), ABSENT_GIT.to_string());
        };
        let mut argv: Vec<OsString> = Vec::new();
        if let Some(ref gd) = self.roots_git {
            argv.push(OsString::from("-C"));
            argv.push(gd.as_os_str().to_os_string());
        }
        for a in args {
            argv.push(OsString::from(a));
        }
        run_proc_bytes(git, &argv, None, &self.git_env(), None, timeout_s)
    }

    pub fn git_str(&self, args: &[&str], timeout_s: u64) -> (i32, String) {
        let (code, out, _) = self.git_bytes(args, timeout_s);
        (code, String::from_utf8_lossy(&out).trim().to_string())
    }

    pub fn git_raw(&self, args: &[&str]) -> (i32, String) {
        let (code, out, _) = self.git_bytes(args, 20);
        (code, String::from_utf8_lossy(&out).into_owned())
    }

    pub fn toplevel(&self) -> Option<PathBuf> {
        let (code, out) = self.git_str(&["rev-parse", "--show-toplevel"], 10);
        if code == 0 && !out.is_empty() {
            Some(PathBuf::from(out))
        } else {
            None
        }
    }

    pub fn evidence_toplevel(&self) -> Option<PathBuf> {
        if let Some(ref ev) = self.roots_evidence {
            return Some(ev.clone());
        }
        let git = self.git_bin.as_deref()?;
        let args = vec![
            OsString::from("rev-parse"),
            OsString::from("--show-toplevel"),
        ];
        let (code, out, _) = run_proc_bytes(git, &args, None, &self.git_env(), None, 20);
        let s = String::from_utf8_lossy(&out).trim().to_string();
        if code == 0 && !s.is_empty() {
            Some(PathBuf::from(s))
        } else {
            None
        }
    }

    pub fn roots_are_split(&mut self) -> bool {
        if self.roots_git.is_none() && self.roots_evidence.is_none() {
            return false;
        }
        if let Some(cached) = self.split_cache {
            return cached;
        }
        let sha_top = self.toplevel();
        let ev_top = self.evidence_toplevel();
        let split = match (sha_top, ev_top) {
            (Some(a), Some(b)) => match (fs::canonicalize(a), fs::canonicalize(b)) {
                (Ok(ra), Ok(rb)) => ra != rb,
                _ => true,
            },
            _ => true,
        };
        self.split_cache = Some(split);
        split
    }

    pub fn infer_repo(&self) -> Option<String> {
        let (code, url) = self.git_str(&["remote", "get-url", "origin"], 10);
        if code != 0 {
            return None;
        }
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"[:/]([^/]+/[^/]+?)(?:\.git)?$").expect("regex"));
        re.captures(url.trim()).map(|c| c[1].to_string())
    }

    pub fn tree_of(&self, sha: &str) -> Option<String> {
        let spec = format!("{sha}^{{tree}}");
        let (code, out) = self.git_str(&["rev-parse", &spec], 10);
        if code == 0 && !out.is_empty() {
            Some(out)
        } else {
            None
        }
    }

    pub fn resolve_evidence(&self, path: &str) -> (Option<PathBuf>, Option<String>) {
        let p = Path::new(path);
        if p.is_absolute() {
            return (
                None,
                Some(format!(
                    "absolute evidence path refused — must be repo-relative (#267): {path}"
                )),
            );
        }
        let bound = if self.roots_evidence.is_some() {
            "the evidence root"
        } else {
            "the repo toplevel"
        };
        if matches!(p.components().next(), Some(Component::ParentDir)) {
            return (
                None,
                Some(format!("evidence path escapes {bound} (#267): {path}")),
            );
        }
        let Some(top) = self.evidence_toplevel() else {
            return (
                None,
                Some(
                    "not inside a git repo — no toplevel to bound the evidence path against (#267)"
                        .to_string(),
                ),
            );
        };
        let root = match fs::canonicalize(&top) {
            Ok(r) => r,
            Err(e) => return (None, Some(e.to_string())),
        };
        let full = resolve_non_strict(&root.join(p));
        if full != root && !full.starts_with(&root) {
            return (
                None,
                Some(format!("evidence path escapes {bound} (#267): {path}")),
            );
        }
        (Some(full), None)
    }

    pub fn read_source(&self, source: &str) -> (Option<Vec<u8>>, Option<String>) {
        if source.is_empty() {
            return (None, Some("missing".to_string()));
        }
        if let Some((path, ref_name)) = source.split_once('@') {
            if !ref_name.is_empty() {
                if path.starts_with('-') || ref_name.starts_with('-') {
                    return (
                        None,
                        Some(
                            "refusing option-like ref/path (leading '-') — see git-option-injection guard"
                                .to_string(),
                        ),
                    );
                }
                if Path::new(path).is_absolute() {
                    return (
                        None,
                        Some(format!(
                            "absolute path refused in a path@ref source (#267): {path}"
                        )),
                    );
                }
                let spec = format!("{ref_name}:{}", pathlib_posix(path));
                let (code, out, err) = self.git_bytes(&["show", &spec], 20);
                return if code == 0 {
                    (Some(out), None)
                } else {
                    let msg = err.trim();
                    (
                        None,
                        Some(if msg.is_empty() {
                            "git ref not found".to_string()
                        } else {
                            msg.to_string()
                        }),
                    )
                };
            }
        }
        let (resolved, err) = self.resolve_evidence(source);
        if let Some(e) = err {
            return (None, Some(e));
        }
        match fs::read(resolved.expect("resolved")) {
            Ok(b) => (Some(b), None),
            Err(e) => (None, Some(e.to_string())),
        }
    }

    /// Exact-name trust anchor check (W3-07) using this verifier's pinned `git_bin` + `git_env`.
    pub fn anchor_commit(&self, name: &str) -> (Option<String>, String, Option<String>) {
        if name.is_empty() || name.starts_with('-') {
            return (
                None,
                name.to_string(),
                Some("is empty or starts with '-'".to_string()),
            );
        }
        if name.contains('\0') || name.contains('\n') || name.contains('\r') {
            return (
                None,
                name.to_string(),
                Some("contains control characters".to_string()),
            );
        }
        let low = name.to_ascii_lowercase();
        if hex40_or_64_re().is_match(&low) {
            let (code, ty) = self.git_str(&["cat-file", "-t", &low], 10);
            if code == 0 && ty == "commit" {
                // Verify object length matches repo object format
                let (cf, fmt) = self.git_str(&["rev-parse", "--show-object-format"], 10);
                let expected_len = if cf == 0 && fmt == "sha256" { 64 } else { 40 };
                if low.len() == expected_len {
                    return (Some(low.clone()), low, None);
                }
            }
            return (
                None,
                name.to_string(),
                Some("does not name a commit object in this repository".to_string()),
            );
        }
        if !name.starts_with("refs/remotes/") {
            return (
                None,
                name.to_string(),
                Some(
                    "is not a commit id or a full refs/remotes/... remote-tracking ref".to_string(),
                ),
            );
        }
        let mut cur = name.to_string();
        let mut seen = HashSet::new();
        for _ in 0..8 {
            if !seen.insert(cur.clone()) {
                return (None, cur, Some("is a cyclic symbolic ref".to_string()));
            }
            let (sc, sym_raw) = self.git_raw(&["symbolic-ref", "-q", &cur]);
            if sc == 0 {
                let target = sym_raw.strip_suffix('\n').unwrap_or(&sym_raw).to_string();
                if !target.starts_with("refs/remotes/") {
                    return (
                        None,
                        target.clone(),
                        Some(format!(
                            "is a symbolic ref targeting non-remote-tracking ref {target:?}"
                        )),
                    );
                }
                cur = target;
                continue;
            }
            // Must exist under exact name in for-each-ref
            let (fc, list_raw) = self.git_raw(&[
                "for-each-ref",
                "--format=%(objecttype) %(objectname) %(refname)",
                &cur,
            ]);
            if fc != 0 {
                return (None, cur, Some("cannot be queried in refs".to_string()));
            }
            for line in list_raw.split('\n') {
                if line.is_empty() {
                    continue;
                }
                let mut parts = line.splitn(3, ' ');
                let ty = parts.next().unwrap_or("");
                let oid = parts.next().unwrap_or("");
                let rname = parts.next().unwrap_or("");
                if rname == cur {
                    if ty == "commit" && hex40_or_64_re().is_match(oid) {
                        return (Some(oid.to_string()), cur, None);
                    }
                    return (None, cur, Some(format!("points to a {ty}, not a commit")));
                }
            }
            return (
                None,
                cur,
                Some("does not exist under that exact remote-tracking ref name".to_string()),
            );
        }
        (None, cur, Some("symbolic ref chain too deep".to_string()))
    }

    /// `(where_desc, read_source, pinned, refusal)` — exact W3-03/W3-07 port.
    pub fn key_source(
        &self,
        source: &str,
        what: &str,
        probe_git: bool,
    ) -> (String, String, bool, Option<String>) {
        let sound = self.lane.is_some();
        let (path, ref_opt) = match source.split_once('@') {
            Some((p, r)) if !r.is_empty() => (p, Some(r)),
            _ => (source, None),
        };
        let (mut where_s, read_s, pinned) = match ref_opt {
            None => (
                format!("the working-tree file {path} (the graded worker can write it)"),
                source.to_string(),
                false,
            ),
            Some(r) if r.starts_with('-') => {
                return (format!("{path} at {r:?}"), source.to_string(), false, None);
            }
            Some(r) if !probe_git => {
                let p = r.starts_with("refs/remotes/")
                    || hex40_or_64_re().is_match(&r.to_ascii_lowercase());
                (format!("{path} at {r:?}"), source.to_string(), p)
            }
            Some(r) => {
                let (commit, target, why) = self.anchor_commit(r);
                if let Some(c) = commit {
                    let short = &c[..12.min(c.len())];
                    let w = if target == c {
                        format!("{path} at commit {short}")
                    } else {
                        let via = if target != r {
                            format!(" (a symbolic ref to {target})")
                        } else {
                            String::new()
                        };
                        format!("{path} at remote-tracking ref {r}{via} = commit {short}")
                    };
                    (w, format!("{path}@{c}"), true)
                } else {
                    let spec = format!("{r}^{{commit}}");
                    let (code, local) = self.git_str(&["rev-parse", "--verify", "-q", &spec], 10);
                    if code != 0 || !hex40_or_64_re().is_match(&local) {
                        (
                            format!("{path} at {r:?}, which names no commit"),
                            source.to_string(),
                            false,
                        )
                    } else {
                        let short = &local[..12.min(local.len())];
                        let why_s = why.unwrap_or_default();
                        (
                            format!(
                                "{path} at {r:?} = commit {short}, a local name the graded worker can move ({r:?} {why_s})"
                            ),
                            format!("{path}@{local}"),
                            false,
                        )
                    }
                }
            }
        };
        if !pinned && sound {
            let lane_s = self.lane.as_deref().unwrap_or("");
            return (
                where_s.clone(),
                read_s,
                false,
                Some(format!(
                    "{what} {source:?} is {where_s} — a lane claiming soundness ({lane_s}) \
                     reads trust material only at a commit id or a full remote-tracking ref \
                     that exists under exactly that name (what the coordinator's own fetch wrote): \
                     path@refs/remotes/… or path@<commit id>; fail-closed (W3-03, W3-07)"
                )),
            );
        }
        if pinned {
            where_s.push_str(
                " — trustworthy only where the worker cannot write refs (the coordinator's \
                 own fetch, a CI checkout); in the worker's own clone this lane is advisory",
            );
        }
        (where_s, read_s, pinned, None)
    }

    pub fn classify(&self, path: &Path) -> String {
        let abs = abspath(path);
        let Ok(nodes) = walk_nodes(&abs) else {
            return "worker-writable".to_string();
        };
        let Ok(real) = fs::canonicalize(&abs) else {
            return "worker-writable".to_string();
        };
        if nodes.iter().any(|(n, st)| worker_controls(n, st)) {
            return "worker-writable".to_string();
        }
        let cwd = env::current_dir().ok();
        let tmp = env::temp_dir();
        let mut candidate_roots: Vec<PathBuf> = vec![tmp];
        if let Some(ref c) = cwd {
            candidate_roots.push(c.clone());
            if let Some(gt) = fs_git_toplevel(c) {
                candidate_roots.push(gt);
            }
        }
        if let Some(ref rg) = self.roots_git {
            candidate_roots.push(rg.clone());
            if let Some(gt) = fs_git_toplevel(rg) {
                candidate_roots.push(gt);
            }
        }
        if let Some(ref re) = self.roots_evidence {
            candidate_roots.push(re.clone());
            if let Some(gt) = fs_git_toplevel(re) {
                candidate_roots.push(gt);
            }
        }
        for root in candidate_roots {
            let Ok(r) = fs::canonicalize(&root) else {
                continue;
            };
            if r.parent().is_none() {
                continue;
            }
            if real == r
                || real.starts_with(&r)
                || nodes.iter().any(|(n, _)| n == &r || n.starts_with(&r))
            {
                return "worker-writable".to_string();
            }
        }
        "system".to_string()
    }

    pub fn authority_leg(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.git_custody.as_deref() == Some("worker-writable") {
            let git_s = self
                .git_bin
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let where_s = format!("git at {git_s} is worker-writable");
            if let Some(ref lane) = self.lane {
                return vec![format!(
                    "authority: {where_s} — a lane claiming soundness ({lane}) cannot take \
                     its commit, tree and ancestry facts from a binary the graded worker could \
                     have replaced; fail-closed (h409 R2)"
                )];
            }
            lines.push(format!("NOTE: authority: advisory ({where_s})"));
        }
        if self.gitleaks_custody.as_deref() == Some("worker-writable") {
            let gl_s = self
                .gitleaks_bin
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            if let Some(ref lane) = self.lane {
                lines.push(format!(
                    "NOTE: redaction: gitleaks at {gl_s} is worker-writable — on a \
                     lane claiming soundness ({lane}) it is NOT run; only the built-in \
                     floor scanned the evidence (W3-10)"
                ));
            } else {
                lines.push(format!(
                    "NOTE: redaction: gitleaks at {gl_s} is worker-writable — it can \
                     only add hits above the built-in floor, so it is consulted and recorded (h409 R2)"
                ));
            }
        }
        lines
    }

    pub fn review_leg(&self, repo: &str) -> Vec<String> {
        let mut lines = Vec::new();
        if self.gh_custody.as_deref() == Some("absent") {
            if let Some(ref lane) = self.lane {
                return vec![format!(
                    "review_authority: {ABSENT_GH} — a lane claiming soundness ({lane}) has \
                     no independent review authority to consult; fail-closed"
                )];
            }
            lines.push(format!("NOTE: review_authority: advisory ({ABSENT_GH})"));
        }
        if self.gh_custody.as_deref() == Some("worker-writable") {
            let gh_s = self
                .gh_bin
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let where_s = format!("gh at {gh_s} is worker-writable");
            if let Some(ref lane) = self.lane {
                return vec![format!(
                    "review_authority: {where_s} — a lane claiming soundness ({lane}) cannot \
                     take its independent review from a binary the graded worker could have \
                     replaced; fail-closed (h409 F-1)"
                )];
            }
            lines.push(format!("NOTE: review_authority: advisory ({where_s})"));
        }
        if self.repo_source.as_deref() == Some("inferred") {
            if let Some(ref lane) = self.lane {
                return vec![format!(
                    "review_repo: {repo:?} was inferred from the clone's origin, which the \
                     worker controls — a lane claiming soundness ({lane}) requires an \
                     explicit --repo; fail-closed (h409 F-2)"
                )];
            }
            lines.push(format!(
                "NOTE: review_repo: advisory ({repo:?} inferred from origin, not pinned by the coordinator)"
            ));
        }
        lines
    }

    pub fn gh_api(
        &self,
        repo: &str,
        endpoint: &str,
        flags: &[&str],
        timeout_s: u64,
    ) -> (i32, String, String) {
        let Some(gh) = self.gh_bin.as_deref() else {
            return (1, String::new(), ABSENT_GH.to_string());
        };
        let (host, slug) = split_repo(repo);
        let mut argv: Vec<OsString> = vec![OsString::from("api")];
        for f in flags {
            argv.push(OsString::from(f));
        }
        if let Some(h) = host {
            argv.push(OsString::from("--hostname"));
            argv.push(OsString::from(h));
        }
        argv.push(OsString::from(format!("repos/{slug}/{endpoint}")));
        let (code, out, err) = run_proc_bytes(gh, &argv, None, &self.gh_env(), None, timeout_s);
        (code, String::from_utf8_lossy(&out).into_owned(), err)
    }

    pub fn command_oracle_paths(&self, command: Option<&str>) -> Option<HashSet<String>> {
        let cmd = match command {
            Some(c) if !c.is_empty() => c,
            _ => return Some(HashSet::new()),
        };
        let argv = shlex_split(cmd, false).ok()?;
        if argv.is_empty() {
            return Some(HashSet::new());
        }
        let indexed = unwrap_nc_indexed(&argv, false).ok()?;
        if indexed.is_empty() {
            return None;
        }
        let wrapper_names: Vec<String> = indexed[..indexed.len() - 1]
            .iter()
            .map(|(_, tok)| basename_of(tok))
            .collect();
        if wrapper_names.iter().any(|n| n == "nice")
            || wrapper_names.iter().filter(|n| n.as_str() == "env").count() > 1
        {
            return None;
        }
        let mut inputs: Vec<String> = indexed.iter().map(|(_, t)| t.clone()).collect();
        let (target_idx, target_tok) = indexed.last().expect("non-empty");
        let tail = &argv[*target_idx..];
        let program = basename_of(target_tok);
        let is_python = python_name_re().is_match(&program);
        let is_shell = is_shell_name(&program);
        let other_interp = other_interp_re().is_match(&program);
        let mut is_pytest = pytest_name_re().is_match(&program);
        let is_grep = grep_name_re().is_match(&program);
        let is_make = make_name_re().is_match(&program);
        let mut module: Option<String> = None;
        let mut scan_from = 1usize;

        if is_shell {
            let script_op = parse_shell_script_operand(target_tok, &tail[1..]).ok()?;
            inputs.push(script_op.clone());
            let mut si = 1usize;
            while si < tail.len() {
                if tail[si] == "--" {
                    si += 1;
                    break;
                }
                if tail[si] == script_op {
                    break;
                }
                si += if tail[si] == "-o" || tail[si] == "+o" {
                    2
                } else {
                    1
                };
            }
            scan_from = if si < tail.len() && tail[si] == script_op {
                si + 1
            } else {
                tail.len()
            };
        } else if is_python || other_interp {
            let mut i = 1usize;
            while is_python
                && i < tail.len()
                && matches!(
                    tail[i].as_str(),
                    "-B" | "-E" | "-I" | "-O" | "-OO" | "-s" | "-S" | "-u" | "-q"
                )
            {
                i += 1;
            }
            if i >= tail.len() {
                return None;
            }
            let arg = &tail[i];
            if is_python && arg.starts_with("-m") {
                let mname = if arg == "-m" {
                    tail.get(i + 1).map(|s| s.as_str()).unwrap_or("")
                } else {
                    &arg[2..]
                };
                if !dotted_ident_re().is_match(mname) {
                    return None;
                }
                let mod_root = mname.split('.').next().unwrap_or("");
                if mod_root != "unittest" && FORBID_PY_MODS.contains(&mod_root) {
                    return None;
                }
                if mname != "pytest" && mname != "unittest" && tail[1..i].iter().any(|x| x == "-I")
                {
                    return None;
                }
                module = Some(mname.replace('.', "/"));
                scan_from = if arg == "-m" { i + 2 } else { i + 1 };
                if mname == "pytest" {
                    is_pytest = true;
                }
            } else {
                if arg == "--" {
                    i += 1;
                }
                if i >= tail.len() || tail[i].starts_with('-') {
                    return None;
                }
                if program.starts_with("node") && matches!(tail[i].as_str(), "inspect" | "debug") {
                    return None;
                }
                inputs.push(tail[i].clone());
                scan_from = i + 1;
            }
        } else if is_make {
            let mut i = 1usize;
            while i < tail.len() {
                let arg = &tail[i];
                if matches!(arg.as_str(), "-f" | "--file" | "--makefile") && i + 1 < tail.len() {
                    i += 1;
                    inputs.push(tail[i].clone());
                } else if let Some(v) = arg
                    .strip_prefix("--file=")
                    .or_else(|| arg.strip_prefix("--makefile="))
                {
                    inputs.push(v.to_string());
                } else if let Some(v) = arg.strip_prefix("-f") {
                    if !v.is_empty() {
                        inputs.push(v.to_string());
                    } else {
                        return None;
                    }
                } else if arg.starts_with('-') || arg.contains('=') {
                    return None;
                }
                i += 1;
            }
            scan_from = tail.len();
        } else if !(is_grep || is_pytest) {
            return None;
        }

        let value_opts: &[&str] = if is_pytest { &["-f", "-c"] } else { &["-f"] };
        let long_opts = ["--config", "--config-file", "--file"];
        let mut i = scan_from;
        while i < tail.len() {
            let arg = &tail[i];
            if arg == "--" {
                break;
            }
            if let Some(val) = long_opts
                .iter()
                .find_map(|opt| arg.strip_prefix(&format!("{opt}=")))
            {
                inputs.push(val.to_string());
            } else if (long_opts.contains(&arg.as_str()) || value_opts.contains(&arg.as_str()))
                && i + 1 < tail.len()
            {
                i += 1;
                inputs.push(tail[i].clone());
            } else if value_opts.iter().any(|o| arg.starts_with(o)) && arg.len() > 2 {
                inputs.push(arg[2..].to_string());
            } else if arg.len() > 1
                && arg.starts_with('-')
                && !arg.starts_with("--")
                && value_opts
                    .iter()
                    .any(|o| arg[1..].contains(o.chars().nth(1).unwrap_or(' ')))
            {
                return None;
            }
            i += 1;
        }

        let top = self.toplevel();
        let mut paths = HashSet::new();
        for value in inputs {
            let normed = normpath_str(&value);
            let cand = Path::new(&normed);
            if cand.is_absolute() {
                if let Some(ref t) = top {
                    if let Ok(rel) = cand.strip_prefix(t) {
                        paths.insert(path_to_posix(rel));
                    }
                }
                continue;
            }
            paths.insert(pathlib_posix(&normed));
        }
        if let Some(m) = module {
            let mod_parts: Vec<&str> = m.split('/').collect();
            for k in 1..=mod_parts.len() {
                let prefix = mod_parts[..k].join("/");
                paths.insert(format!("{prefix}.py"));
                paths.insert(format!("{prefix}/__init__.py"));
            }
            paths.insert(format!("{m}/__main__.py"));
        }
        Some(paths)
    }

    pub fn is_oracle_path(
        &mut self,
        path: &str,
        nc_command: Option<&str>,
        head: Option<&str>,
    ) -> Result<bool, String> {
        let leaf_low = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            leaf_low.as_str(),
            "conftest.py"
                | "pytest.ini"
                | ".pytest.ini"
                | "pytest.toml"
                | ".pytest.toml"
                | "tox.ini"
                | "setup.cfg"
                | "pyproject.toml"
                | "package.json"
                | ".coveragerc"
                | "makefile"
                | "gnumakefile"
        ) {
            return Ok(true);
        }
        if js_test_config_re().is_match(&path.to_ascii_lowercase()) {
            return Ok(true);
        }
        let Some(inputs) = self.command_oracle_paths(nc_command) else {
            return Err("unsupported proof command; fail-closed".to_string());
        };
        let norm_p = pathlib_posix(path);
        if norm_p.to_ascii_lowercase().ends_with(".mk") || inputs.contains(&norm_p) {
            return Ok(true);
        }
        if let Some(h) = head {
            let key = (h.to_string(), nc_command.map(|s| s.to_string()));
            if !self.discovery_cache.contains_key(&key) {
                let res = self.discover_runner_tests(h, nc_command);
                self.discovery_cache.insert(key.clone(), res);
            }
            match self.discovery_cache.get(&key) {
                Some(Ok(matcher)) => {
                    if matcher.matches(&norm_p) {
                        return Ok(true);
                    }
                }
                Some(Err(e)) => return Err(e.clone()),
                None => {}
            }
        }
        Ok(is_test_path(path))
    }

    fn discover_runner_tests(
        &self,
        head: &str,
        command: Option<&str>,
    ) -> Result<DiscoveryMatcher, String> {
        let top = self.toplevel().unwrap_or_else(|| PathBuf::from("/"));
        let rel = |value: &str| -> Option<String> {
            let base = value.split("::").next().unwrap_or(value);
            let mut p = normpath_str(base);
            if Path::new(&p).is_absolute() {
                if let Ok(r) = Path::new(&p).strip_prefix(&top) {
                    p = path_to_posix(r);
                } else {
                    return None;
                }
            }
            let posix = pathlib_posix(&p);
            if posix == ".." || posix.starts_with("../") {
                None
            } else if posix == "." {
                Some(String::new())
            } else {
                Some(posix)
            }
        };

        let mut argv = match command {
            Some(c) if !c.is_empty() => shlex_split(c, false).unwrap_or_default(),
            _ => Vec::new(),
        };
        if argv.first().is_some_and(|a| basename_of(a) == "env") {
            let drop_n = if argv.get(1).is_some_and(|x| x == "--") {
                2
            } else {
                1
            };
            if drop_n <= argv.len() {
                argv = argv[drop_n..].to_vec();
            }
        }
        let prog = argv.first().map(|a| basename_of(a)).unwrap_or_default();
        let (mut runner, mut rest): (Option<&str>, Vec<String>) = if prog == "pytest" {
            (Some("pytest"), argv[1..].to_vec())
        } else {
            (None, Vec::new())
        };
        if python_name_re().is_match(&prog) {
            let mut i = 1usize;
            while i < argv.len()
                && matches!(
                    argv[i].as_str(),
                    "-B" | "-E" | "-I" | "-O" | "-OO" | "-s" | "-S" | "-u" | "-q"
                )
            {
                i += 1;
            }
            if let Some(arg) = argv.get(i) {
                if let Some(stripped) = arg.strip_prefix("-m") {
                    let name = if stripped.is_empty() {
                        argv.get(i + 1).map(|s| s.as_str()).unwrap_or("")
                    } else {
                        stripped
                    };
                    if name == "pytest" || name == "unittest" {
                        runner = Some(if name == "pytest" {
                            "pytest"
                        } else {
                            "unittest"
                        });
                        let next_i = i + if stripped.is_empty() { 2 } else { 1 };
                        rest = argv.get(next_i..).unwrap_or(&[]).to_vec();
                    }
                }
            }
        }

        let mut ops: Vec<String> = Vec::new();
        let mut opt: HashMap<String, Vec<String>> = HashMap::new();
        let valued = |r: Option<&str>, k: &str| -> Option<&'static str> {
            match r {
                Some("pytest") => match k {
                    "-c" | "--config-file" => Some("c"),
                    "-o" | "--override-ini" => Some("o"),
                    "--rootdir" | "-k" | "-m" | "-p" => Some(""),
                    _ => None,
                },
                Some("unittest") => match k {
                    "-p" | "--pattern" => Some("p"),
                    "-s" | "--start-directory" => Some("s"),
                    "-t" | "--top-level-directory" | "-k" => Some(""),
                    _ => None,
                },
                _ => None,
            }
        };
        let mut i = 0usize;
        let mut after = false;
        while i < rest.len() {
            let tok = &rest[i];
            if after || !tok.starts_with('-') {
                ops.push(tok.clone());
            } else if tok == "--" {
                after = true;
            } else if let Some(slot) = valued(runner, tok) {
                let val = rest.get(i + 1).cloned().unwrap_or_default();
                opt.entry(slot.to_string()).or_default().push(val);
                i += 1;
            } else if tok.starts_with("--") {
                if let Some((lk, lv)) = tok.split_once('=') {
                    if let Some(slot) = valued(runner, lk) {
                        opt.entry(slot.to_string())
                            .or_default()
                            .push(lv.to_string());
                    }
                }
            } else if ((runner == Some("pytest")
                && (tok.starts_with("-c") || tok.starts_with("-o")))
                || (runner == Some("unittest") && (tok.starts_with("-p") || tok.starts_with("-s"))))
                && tok.len() > 2
            {
                opt.entry(tok[1..2].to_string())
                    .or_default()
                    .push(tok[2..].to_string());
            }
            i += 1;
        }

        let configs = opt.get("c").cloned().unwrap_or_default();
        let mut overrides: HashMap<String, Vec<String>> = HashMap::new();
        for pair in opt.get("o").cloned().unwrap_or_default() {
            let (k, v) = pair.split_once('=').unwrap_or((pair.as_str(), ""));
            overrides
                .entry(k.trim().to_string())
                .or_default()
                .extend(split_words_str(v));
        }

        let mut exact: HashSet<String> = HashSet::new();
        let mut dirs: BTreeSet<String> = BTreeSet::new();
        dirs.insert(String::new());
        let mut roots: Vec<String> = Vec::new();

        if runner == Some("unittest") && ops.first().map(|s| s.as_str()) == Some("discover") {
            if let Some(s_arg) = ops.get(1) {
                opt.entry("s".to_string()).or_default().push(s_arg.clone());
            }
            if let Some(p_arg) = ops.get(2) {
                opt.entry("p".to_string()).or_default().push(p_arg.clone());
            }
        } else if runner == Some("unittest") {
            for op in &ops {
                if dotted_ident_re().is_match(op) {
                    let parts: Vec<&str> = op.split('.').collect();
                    let mut cands: Vec<String> = Vec::new();
                    for k in 1..=parts.len() {
                        let base = parts[..k].join("/");
                        cands.push(format!("{base}.py"));
                        cands.push(format!("{base}/__init__.py"));
                    }
                    let mut git_args: Vec<&str> = vec![
                        "--literal-pathspecs",
                        "ls-tree",
                        "--full-tree",
                        "-r",
                        "-z",
                        "--name-only",
                        head,
                        "--",
                    ];
                    let cand_refs: Vec<&str> = cands.iter().map(|s| s.as_str()).collect();
                    git_args.extend(cand_refs);
                    let (code, found_b, _) = self.git_bytes(&git_args, 10);
                    if code != 0 {
                        return Err(format!(
                            "cannot resolve the unittest operand {op:?} at head_sha {head}; fail-closed (PR #631 review, P1)"
                        ));
                    }
                    let found_s = String::from_utf8_lossy(&found_b);
                    let found_set: HashSet<&str> =
                        found_s.split('\0').filter(|s| !s.is_empty()).collect();
                    let present: Vec<&String> = cands
                        .iter()
                        .filter(|c| found_set.contains(c.as_str()))
                        .collect();
                    if let Some(last) = present.last() {
                        exact.insert((*last).clone());
                    } else {
                        exact.extend(cands);
                    }
                } else if let Some(r) = rel(op) {
                    if !r.is_empty() {
                        exact.insert(r);
                    }
                }
            }
        } else {
            for op in &ops {
                if let Some(p) = rel(op) {
                    roots.push(p.clone());
                    if !p.is_empty() {
                        exact.insert(p.clone());
                        let parts: Vec<&str> = p.split('/').collect();
                        for k in 0..=parts.len() {
                            dirs.insert(parts[..k].join("/"));
                        }
                    }
                }
            }
        }

        let cfg_names = [
            "pytest.ini",
            ".pytest.ini",
            "pytest.toml",
            ".pytest.toml",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
        ];
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        wanted.insert("package.json".to_string());
        for d in &dirs {
            for n in cfg_names {
                let combined = if d.is_empty() {
                    n.to_string()
                } else {
                    format!("{d}/{n}")
                };
                wanted.insert(combined);
            }
        }
        for c in &configs {
            if let Some(r) = rel(c) {
                if !r.is_empty() {
                    wanted.insert(r);
                }
            }
        }
        let wanted_vec: Vec<String> = wanted.into_iter().collect();
        let mut ls_args: Vec<&str> = vec![
            "--literal-pathspecs",
            "ls-tree",
            "--full-tree",
            "-r",
            "-z",
            "--name-only",
            head,
            "--",
        ];
        ls_args.extend(wanted_vec.iter().map(|s| s.as_str()));
        let (code, listing_b, _) = self.git_bytes(&ls_args, 10);
        if code != 0 {
            return Err(format!(
                "cannot list the test-discovery configuration at head_sha {head}; fail-closed (2026-10-23 review, P2-1)"
            ));
        }
        let listing_s = String::from_utf8_lossy(&listing_b);
        let mut cfg_files: Vec<String> = listing_s
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        cfg_files.sort();

        let mut py_globs: Vec<String> = overrides.get("python_files").cloned().unwrap_or_default();
        let mut testpaths: Vec<String> = overrides
            .get("testpaths")
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| rel(t))
            .collect();
        let mut regexes: Vec<Regex> = Vec::new();

        for cfg in cfg_files {
            let spec = format!("{head}:{cfg}");
            let (c_code, raw, _) = self.git_bytes(&["cat-file", "blob", &spec], 20);
            let parse_res: Result<(), String> = (|| {
                if c_code != 0 {
                    return Err("unreadable at head_sha".to_string());
                }
                let text = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
                if cfg == "package.json" {
                    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
                    if let Some(jest) = doc.get("jest").and_then(|v| v.as_object()) {
                        if let Some(rx_v) = jest.get("testRegex") {
                            let list: Vec<String> = match rx_v {
                                Value::String(s) => vec![s.clone()],
                                Value::Array(arr) => arr
                                    .iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect(),
                                Value::Null => Vec::new(),
                                _ => return Err("invalid jest testRegex".to_string()),
                            };
                            for pat in list {
                                let re = Regex::new(&pat).map_err(|e| e.to_string())?;
                                regexes.push(re);
                            }
                        }
                        if let Some(tm_v) = jest.get("testMatch") {
                            for g in words_from_value(tm_v) {
                                if g.starts_with('!') {
                                    continue;
                                }
                                let stripped = g.replace("<rootDir>/", "");
                                let body = glob_to_regex(&stripped)?;
                                let re =
                                    Regex::new(&format!("^/{body}$")).map_err(|e| e.to_string())?;
                                regexes.push(re);
                            }
                        }
                    }
                    return Ok(());
                }
                let cfg_dir = cfg.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                if cfg.ends_with(".toml") {
                    let dedicated = Path::new(&cfg)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| !n.eq_ignore_ascii_case("pyproject.toml"))
                        .unwrap_or(false);
                    let val: toml::Value =
                        text.parse().map_err(|e: toml::de::Error| e.to_string())?;
                    let mut sections: Vec<&toml::Table> = Vec::new();
                    if let Some(tool_pt) = val
                        .get("tool")
                        .and_then(|v| v.get("pytest"))
                        .and_then(|v| v.as_table())
                    {
                        if let Some(ini) = tool_pt.get("ini_options").and_then(|v| v.as_table()) {
                            sections.push(ini);
                        }
                        sections.push(tool_pt);
                    }
                    if dedicated {
                        if let Some(pt) = val.get("pytest").and_then(|v| v.as_table()) {
                            sections.push(pt);
                        }
                    }
                    for sec in sections {
                        if let Some(pf) = sec.get("python_files") {
                            py_globs.extend(words_from_toml(pf));
                        }
                        if let Some(tp) = sec.get("testpaths") {
                            for t in words_from_toml(tp) {
                                let joined = if cfg_dir.is_empty() {
                                    t
                                } else {
                                    format!("{cfg_dir}/{t}")
                                };
                                if let Some(r) = rel(&joined) {
                                    testpaths.push(r);
                                }
                            }
                        }
                    }
                } else {
                    let sections = parse_ini_pytest_sections(text)?;
                    for sec in sections {
                        if let Some(pf) = sec.get("python_files") {
                            py_globs.extend(split_words_str(pf));
                        }
                        if let Some(tp) = sec.get("testpaths") {
                            for t in split_words_str(tp) {
                                let joined = if cfg_dir.is_empty() {
                                    t
                                } else {
                                    format!("{cfg_dir}/{t}")
                                };
                                if let Some(r) = rel(&joined) {
                                    testpaths.push(r);
                                }
                            }
                        }
                    }
                }
                Ok(())
            })();
            if let Err(exc) = parse_res {
                return Err(format!(
                    "the test-discovery configuration {cfg} at head_sha cannot be read \
                     ({exc}), so a test path cannot be told from a production one; \
                     fail-closed (2026-10-23 review, P2-1)"
                ));
            }
        }

        let py_roots = if !testpaths.is_empty() {
            let mut r = roots.clone();
            r.extend(testpaths);
            r
        } else {
            vec![String::new()]
        };
        if py_globs.is_empty() {
            py_globs = vec!["test_*.py".to_string(), "*_test.py".to_string()];
        }
        let ut_globs = if runner == Some("unittest") {
            opt.get("p")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| vec!["test*.py".to_string()])
        } else {
            Vec::new()
        };
        let ut_roots: Vec<String> = opt
            .get("s")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| vec![".".to_string()])
            .iter()
            .filter_map(|s| rel(s))
            .collect();

        Ok(DiscoveryMatcher {
            exact,
            py_roots,
            py_globs,
            ut_roots,
            ut_globs,
            regexes,
        })
    }

    pub fn nc_exec_identity(
        &self,
        argv: &[String],
        top: Option<&Path>,
        path_env: Option<&str>,
        expected: Option<&[PinnedExecRec]>,
        when: Option<&str>,
    ) -> Result<Vec<PinnedExecRec>, String> {
        if argv.is_empty() {
            return Err("negative_control.command is empty after parsing".to_string());
        }
        let indexed = unwrap_nc_indexed(argv, true)?;
        let search_path: String = match path_env {
            Some(p) => p.to_string(),
            None => self
                .nc_env()
                .into_iter()
                .find(|(k, _)| k == "PATH")
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        let mut roots: Vec<PathBuf> = Vec::new();
        for cand in [
            top.map(|p| p.to_path_buf()),
            self.toplevel(),
            self.evidence_toplevel(),
        ]
        .into_iter()
        .flatten()
        {
            if let Ok(r) = fs::canonicalize(&cand) {
                if r.parent().is_some() {
                    roots.push(r);
                }
            }
        }

        let mut records = Vec::new();
        for (argv_idx, tok) in indexed {
            if tok.contains('/') && !Path::new(&tok).is_absolute() {
                return Err(format!(
                    "proof executable {tok:?} uses a relative path containing '/'; fail-closed (#750 C19)"
                ));
            }
            let resolved = if Path::new(&tok).is_absolute() {
                PathBuf::from(&tok)
            } else {
                match which_in(&tok, Some(&search_path)) {
                    Some(p) => p,
                    None => {
                        return Err(format!(
                            "proof executable {tok:?} cannot be resolved on the scrubbed PATH"
                        ));
                    }
                }
            };
            let chain = verify_exec_file_and_shebang(&resolved, &tok, &roots, &search_path, 0)?;
            let tok_base = basename_of(&tok);
            let real_base = basename_of(&chain[0].real_path);
            let eff_real_base = if multicall_box_re().is_match(&real_base)
                && !multicall_box_re().is_match(&tok_base)
            {
                tok_base.clone()
            } else {
                real_base
            };
            let real_fam = exec_family(&eff_real_base);
            let tok_fam = exec_family(&tok_base);
            let sh_emulated_zsh = tok_base == "sh"
                && real_fam == Some("shell:non_posix")
                && rzsh_re().is_match(&eff_real_base);
            if let Some(rf) = real_fam {
                if Some(rf) != tok_fam && !sh_emulated_zsh {
                    return Err(format!(
                        "proof executable {tok:?} resolves to {:?} ({rf}) via alias; invoke the canonical tool name so operands are verified (#750 C19)",
                        chain[0].real_path
                    ));
                }
            }
            records.push(PinnedExecRec {
                argv_idx,
                tok,
                self_rec: chain[0].clone(),
                sub_chain: chain[1..].to_vec(),
            });
        }
        if let Some(exp) = expected {
            if records.as_slice() != exp {
                let w = when.unwrap_or("during");
                return Err(format!("proof executable changed {w} phase; fail-closed"));
            }
        }
        Ok(records)
    }
}

pub fn split_repo(repo: &str) -> (Option<&str>, String) {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
        (Some(parts[0]), format!("{}/{}", parts[1], parts[2]))
    } else {
        (None, repo.to_string())
    }
}

pub fn basename_of(s: &str) -> String {
    Path::new(s)
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or(s)
        .to_string()
}

pub fn is_shell_name(name: &str) -> bool {
    SHELL_NAMES.contains(&name) || shell_re().is_match(name)
}

pub fn is_mux_exe(name: &str) -> bool {
    NC_FORBID_MUX_EXES.contains(&name) || mux_re().is_match(name)
}

pub fn exec_family(name: &str) -> Option<&'static str> {
    if multicall_box_re().is_match(name) {
        return Some("multicall_box");
    }
    if is_mux_exe(name) {
        return Some("mux_wrapper");
    }
    match name {
        "env" | "genv" => return Some("wrap:env"),
        "nice" | "gnice" => return Some("wrap:nice"),
        "timeout" | "gtimeout" => return Some("wrap:timeout"),
        "nohup" | "gnohup" => return Some("wrap:nohup"),
        "command" => return Some("wrap:command"),
        "builtin" => return Some("wrap:builtin"),
        _ => {}
    }
    if non_posix_shell_re().is_match(name) {
        return Some("shell:non_posix");
    }
    if is_shell_name(name) {
        return Some("shell:posix");
    }
    if python_name_re().is_match(name) {
        return Some("interp:python");
    }
    if Regex::new(r"^node(?:js)?(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:node");
    }
    if Regex::new(r"^perl(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:perl");
    }
    if Regex::new(r"^ruby(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:ruby");
    }
    if Regex::new(r"^php(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:php");
    }
    if Regex::new(r"^lua(?:jit)?(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:lua");
    }
    if Regex::new(r"^Rscript(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("interp:Rscript");
    }
    if pytest_name_re().is_match(name) {
        return Some("runner:pytest");
    }
    if make_name_re().is_match(name) {
        return Some("runner:make");
    }
    if grep_name_re().is_match(name) {
        return Some("runner:grep");
    }
    if Regex::new(r"^(?:rg|ripgrep)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
        .expect("re")
        .is_match(name)
    {
        return Some("runner:rg");
    }
    None
}

fn env_var_forbidden(var_name: &str) -> bool {
    if var_name.contains('[') || var_name.contains(']') {
        return true;
    }
    let up = var_name.to_ascii_uppercase();
    if NC_FORBID_ENV_VARS.contains(&up.as_str()) {
        return true;
    }
    NC_FORBID_ENV_PREFIXES.iter().any(|p| up.starts_with(p))
}

fn check_rel_operand(tok: &str, op: &str, label: &str) -> Option<String> {
    if op.is_empty()
        || op == "-"
        || normpath_str(op) == "-"
        || Path::new(op).is_absolute()
        || Path::new(op)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Some(format!(
            "proof executable {tok:?} targets external {label} {op:?} outside the staged commit; fail-closed (#750 C19)"
        ));
    }
    None
}

pub fn parse_shell_script_operand(tok: &str, rest: &[String]) -> Result<String, String> {
    let base = basename_of(tok);
    if non_posix_shell_re().is_match(&base) {
        return Err(format!(
            "proof executable {tok:?} invokes non-POSIX shell or zsh startup files; fail-closed (#750 C19)"
        ));
    }
    let mut si = 0usize;
    while si < rest.len() {
        let arg = &rest[si];
        if arg == "--" || arg == "-" {
            si += 1;
            break;
        }
        if (!arg.starts_with('-') && !arg.starts_with('+')) || arg == "+" {
            break;
        }
        if arg == "-c" || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c'))
        {
            return Err(format!(
                "proof executable {tok:?} invokes a shell -c command string, whose inner commands are unverified (#750 C19)"
            ));
        }
        if arg.starts_with("--") {
            if matches!(arg.as_str(), "--posix" | "--norc" | "--noprofile") {
                si += 1;
                continue;
            }
            return Err(format!(
                "proof executable {tok:?} uses unsupported shell option {arg:?}; fail-closed (#750 C19)"
            ));
        }
        if arg == "-O" || arg == "+O" {
            return Err(format!(
                "proof executable {tok:?} {arg} alters shell lookup/parsing; fail-closed (#750 C19)"
            ));
        }
        if arg == "-o" || arg == "+o" {
            if si + 1 >= rest.len() || !SAFE_SHELL_O_OPTIONS.contains(&rest[si + 1].as_str()) {
                return Err(format!(
                    "proof executable {tok:?} {arg} missing or unsupported option; fail-closed (#750 C19)"
                ));
            }
            si += 2;
            continue;
        }
        let short = &arg[1..];
        if arg.starts_with('-') && short.chars().any(|ch| matches!(ch, 'l' | 'i' | 's' | 'r')) {
            return Err(format!(
                "proof executable {tok:?} invokes interactive/login/stdin shell mode; fail-closed (#750 C19)"
            ));
        }
        if short.chars().any(|ch| !"abefhmnuvxBCHP".contains(ch)) {
            return Err(format!(
                "proof executable {tok:?} uses unsupported shell option {arg:?}; fail-closed (#750 C19)"
            ));
        }
        if short.contains('o') || short.contains('O') {
            let count = short.chars().filter(|&c| c == 'o' || c == 'O').count();
            if !(short.ends_with('o') || short.ends_with('O')) || count != 1 || si + 1 >= rest.len()
            {
                return Err(format!(
                    "proof executable {tok:?} uses ambiguous -o option cluster (#750 C19)"
                ));
            }
            si += 2;
            continue;
        }
        si += 1;
    }
    if si >= rest.len() {
        return Err(format!(
            "proof executable {tok:?} invokes shell without a script operand; fail-closed (#750 C19)"
        ));
    }
    let script_op = &rest[si];
    if !script_op.contains('/')
        || Path::new(script_op).is_absolute()
        || Path::new(script_op)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "proof executable {tok:?} uses bare or external shell script operand {script_op:?}; require a staged repo-relative path containing '/'; fail-closed (#750 C19)"
        ));
    }
    Ok(script_op.clone())
}

pub fn parse_target_operands(tok: &str, rest: &[String]) -> Result<Vec<String>, String> {
    let name = basename_of(tok);
    let mut staged = Vec::new();
    let mut program = name.clone();
    let mut mod_name = String::new();
    let mut scan_idx = 0usize;

    if python_name_re().is_match(&name) {
        let mut pi = 0usize;
        while pi < rest.len()
            && matches!(
                rest[pi].as_str(),
                "-B" | "-E" | "-I" | "-O" | "-OO" | "-s" | "-S" | "-u" | "-q"
            )
        {
            pi += 1;
        }
        if pi >= rest.len() {
            return Err(format!(
                "proof executable {tok:?} missing module or script target; fail-closed (#750 C19)"
            ));
        }
        if rest[pi].starts_with("-m") {
            let m = if rest[pi] == "-m" {
                rest.get(pi + 1).map(|s| s.as_str()).unwrap_or("")
            } else {
                &rest[pi][2..]
            };
            if !dotted_ident_re().is_match(m) {
                return Err(format!(
                    "proof executable {tok:?} uses invalid -m module {m:?}; fail-closed (#750 C19)"
                ));
            }
            mod_name = m.to_string();
            scan_idx = if rest[pi] == "-m" { pi + 2 } else { pi + 1 };
            if m == "pytest" || m == "unittest" {
                program = m.to_string();
            } else {
                let mod_root = m.split('.').next().unwrap_or("");
                if FORBID_PY_MODS.contains(&mod_root) {
                    return Err(format!(
                        "unsupported proof command: {tok:?} invokes module runner '-m {m}'; only '-m pytest', '-m unittest', or a staged repo module is permitted (#750 C19)"
                    ));
                }
                if rest[..pi].iter().any(|x| x == "-I") {
                    return Err(format!(
                        "unsupported proof command: {tok:?} cannot combine '-I' with repo module '-m {m}'; fail-closed (#750 C19)"
                    ));
                }
                program = "py_module".to_string();
            }
        } else {
            if rest[pi] == "--" {
                pi += 1;
            }
            if pi >= rest.len() || rest[pi].starts_with('-') {
                let bad_opt = rest.get(pi).map(|s| s.as_str()).unwrap_or("--");
                return Err(format!(
                    "proof executable {tok:?} uses unsupported interpreter option {bad_opt:?} or missing script; fail-closed (#750 C19)"
                ));
            }
            if let Some(err) = check_rel_operand(tok, &rest[pi], "script") {
                return Err(err);
            }
            staged.push(rest[pi].clone());
            scan_idx = pi + 1;
        }
    } else if other_interp_re().is_match(&name) {
        let pi = usize::from(rest.first().map(|s| s.as_str()) == Some("--"));
        if pi >= rest.len() || rest[pi].starts_with('-') {
            let bad_opt = rest.get(pi).map(|s| s.as_str()).unwrap_or("");
            return Err(format!(
                "proof executable {tok:?} uses unsupported interpreter option {bad_opt:?} or missing script; fail-closed (#750 C19)"
            ));
        }
        if name.starts_with("node") && matches!(rest[pi].as_str(), "inspect" | "debug") {
            return Err(format!(
                "proof executable {tok:?} invokes debugger subcommand {:?}; fail-closed (#750 C19)",
                rest[pi]
            ));
        }
        if let Some(err) = check_rel_operand(tok, &rest[pi], "script") {
            return Err(err);
        }
        staged.push(rest[pi].clone());
        scan_idx = pi + 1;
    } else if make_name_re().is_match(&name) {
        let mut mi = 0usize;
        while mi < rest.len() {
            let a = &rest[mi];
            if matches!(a.as_str(), "-f" | "--file" | "--makefile") {
                if mi + 1 >= rest.len() {
                    return Err(format!(
                        "proof executable {tok:?} {a} missing makefile operand; fail-closed (#750 C19)"
                    ));
                }
                if let Some(err) = check_rel_operand(tok, &rest[mi + 1], "makefile") {
                    return Err(err);
                }
                staged.push(rest[mi + 1].clone());
                mi += 2;
            } else if let Some(v) = a
                .strip_prefix("--file=")
                .or_else(|| a.strip_prefix("--makefile="))
            {
                if let Some(err) = check_rel_operand(tok, v, "makefile") {
                    return Err(err);
                }
                staged.push(v.to_string());
                mi += 1;
            } else if let Some(v) = a.strip_prefix("-f") {
                if !v.is_empty() {
                    if let Some(err) = check_rel_operand(tok, v, "makefile") {
                        return Err(err);
                    }
                    staged.push(v.to_string());
                    mi += 1;
                } else {
                    return Err(format!(
                        "proof executable {tok:?} {a} missing makefile operand; fail-closed (#750 C19)"
                    ));
                }
            } else if a.starts_with('-') || a.contains('=') {
                return Err(format!(
                    "proof executable {tok:?} uses unsupported make argument {a:?}; fail-closed (#750 C19)"
                ));
            } else {
                mi += 1;
            }
        }
        return Ok(staged);
    } else if pytest_name_re().is_match(&name) {
        program = "pytest".to_string();
    } else if grep_name_re().is_match(&name) {
        program = "grep".to_string();
    }

    if program == "unittest" {
        let mut ui = scan_idx;
        let mut u_after = false;
        let mut u_pos: Vec<String> = Vec::new();
        while ui < rest.len() {
            let ua = &rest[ui];
            if !u_after && ua == "--" {
                u_after = true;
                ui += 1;
                continue;
            }
            if u_after || !ua.starts_with('-') {
                u_pos.push(ua.clone());
                ui += 1;
                continue;
            }
            if matches!(
                ua.as_str(),
                "-s" | "--start-directory" | "-t" | "--top-level-directory"
            ) {
                if ui + 1 >= rest.len() {
                    return Err(format!(
                        "proof executable {tok:?} {ua} missing directory operand; fail-closed (#750 C19)"
                    ));
                }
                if let Some(err) = check_rel_operand(tok, &rest[ui + 1], "unittest directory") {
                    return Err(err);
                }
                ui += 2;
                continue;
            }
            if let Some(v) = ua
                .strip_prefix("--start-directory=")
                .or_else(|| ua.strip_prefix("--top-level-directory="))
            {
                if let Some(err) = check_rel_operand(tok, v, "unittest directory") {
                    return Err(err);
                }
                ui += 1;
                continue;
            }
            if (ua.starts_with("-s") || ua.starts_with("-t")) && ua.len() > 2 {
                if let Some(err) = check_rel_operand(tok, &ua[2..], "unittest directory") {
                    return Err(err);
                }
                ui += 1;
                continue;
            }
            if matches!(ua.as_str(), "-p" | "--pattern" | "-k") {
                if ui + 1 >= rest.len() {
                    return Err(format!(
                        "proof executable {tok:?} {ua} missing operand; fail-closed (#750 C19)"
                    ));
                }
                ui += 2;
                continue;
            }
            if (ua.starts_with("--pattern=") || ua.starts_with("-p") || ua.starts_with("-k"))
                && ua.len() > 2
            {
                ui += 1;
                continue;
            }
            if ua.len() > 1
                && ua.starts_with('-')
                && !ua.starts_with("--")
                && ua[1..].chars().any(|c| matches!(c, 's' | 't' | 'p' | 'k'))
            {
                return Err(format!(
                    "proof executable {tok:?} uses ambiguous unittest option cluster {ua:?}; fail-closed (#750 C19)"
                ));
            }
            ui += 1;
        }
        if u_pos.first().map(|s| s.as_str()) == Some("discover") {
            for idx in [1usize, 3usize] {
                if let Some(d_dir) = u_pos.get(idx) {
                    if let Some(err) = check_rel_operand(tok, d_dir, "unittest directory") {
                        return Err(err);
                    }
                }
            }
        } else {
            for u_op in &u_pos {
                if !dotted_ident_re().is_match(u_op) {
                    if let Some(err) = check_rel_operand(tok, u_op, "unittest target") {
                        return Err(err);
                    }
                }
            }
        }
        return Ok(staged);
    }

    let value_opts: &[&str] = if program == "pytest" {
        &["-f", "-c"]
    } else {
        &["-f"]
    };
    let long_opts = ["--config", "--config-file", "--file"];
    let mut saw_grep_pat = false;
    let mut grep_pos: Vec<String> = Vec::new();
    let mut i = scan_idx;
    while i < rest.len() {
        let a = &rest[i];
        if a == "--" {
            break;
        }
        if let Some(val) = long_opts
            .iter()
            .find_map(|o| a.strip_prefix(&format!("{o}=")))
        {
            if let Some(err) = check_rel_operand(tok, val, "config") {
                return Err(err);
            }
            staged.push(val.to_string());
            if program == "grep" {
                saw_grep_pat = true;
            }
            i += 1;
            continue;
        }
        if long_opts.contains(&a.as_str()) {
            if i + 1 >= rest.len() {
                return Err(format!(
                    "proof executable {tok:?} {a} missing operand; fail-closed (#750 C19)"
                ));
            }
            if let Some(err) = check_rel_operand(tok, &rest[i + 1], "config") {
                return Err(err);
            }
            staged.push(rest[i + 1].clone());
            if program == "grep" {
                saw_grep_pat = true;
            }
            i += 2;
            continue;
        }
        if value_opts.contains(&a.as_str()) {
            if i + 1 >= rest.len() {
                return Err(format!(
                    "proof executable {tok:?} {a} missing operand; fail-closed (#750 C19)"
                ));
            }
            if let Some(err) = check_rel_operand(tok, &rest[i + 1], "config") {
                return Err(err);
            }
            staged.push(rest[i + 1].clone());
            if program == "grep" {
                saw_grep_pat = true;
            }
            i += 2;
            continue;
        }
        if value_opts.iter().any(|o| a.starts_with(o)) && a.len() > 2 {
            let val = &a[2..];
            if let Some(err) = check_rel_operand(tok, val, "config") {
                return Err(err);
            }
            staged.push(val.to_string());
            if program == "grep" {
                saw_grep_pat = true;
            }
            i += 1;
            continue;
        }
        if program == "pytest" {
            if matches!(
                a.as_str(),
                "-o" | "-p"
                    | "--override-ini"
                    | "--rootdir"
                    | "--confcutdir"
                    | "--basetemp"
                    | "--import-mode"
                    | "--pyargs"
            ) || a.starts_with("--override-ini=")
                || a.starts_with("--rootdir=")
                || a.starts_with("--confcutdir=")
                || a.starts_with("--basetemp=")
                || a.starts_with("--import-mode=")
                || (a.len() > 1
                    && a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].chars().any(|c| c == 'o' || c == 'p'))
            {
                return Err(format!(
                    "proof executable {tok:?} uses dynamic pytest config/plugin option {a:?}; fail-closed (#750 C19)"
                ));
            }
            if matches!(a.as_str(), "-k" | "-m" | "-W" | "--maxfail") {
                if i + 1 >= rest.len() {
                    return Err(format!(
                        "proof executable {tok:?} {a} missing operand; fail-closed (#750 C19)"
                    ));
                }
                i += 2;
                continue;
            }
            if (a.starts_with("-k") || a.starts_with("-m") || a.starts_with("-W")) && a.len() > 2 {
                i += 1;
                continue;
            }
            if a.len() > 1
                && a.starts_with('-')
                && !a.starts_with("--")
                && a[1..].chars().any(|c| matches!(c, 'k' | 'm' | 'W'))
            {
                return Err(format!(
                    "proof executable {tok:?} uses ambiguous pytest option cluster {a:?}; fail-closed (#750 C19)"
                ));
            }
        }
        if program == "grep" {
            if matches!(a.as_str(), "-e" | "--regexp") {
                if i + 1 >= rest.len() {
                    return Err(format!(
                        "proof executable {tok:?} {a} missing pattern; fail-closed (#750 C19)"
                    ));
                }
                saw_grep_pat = true;
                i += 2;
                continue;
            }
            if a.starts_with("--regexp=") || (a.starts_with("-e") && a.len() > 2) {
                saw_grep_pat = true;
                i += 1;
                continue;
            }
        }
        if a.len() > 1
            && a.starts_with('-')
            && !a.starts_with("--")
            && value_opts
                .iter()
                .any(|o| a[1..].contains(o.chars().nth(1).unwrap_or(' ')))
        {
            return Err(format!(
                "proof executable {tok:?} uses ambiguous option cluster {a:?}; fail-closed (#750 C19)"
            ));
        } else if program == "pytest" && !a.starts_with('-') {
            let p_part = a.split("::").next().unwrap_or(a);
            if let Some(err) = check_rel_operand(tok, p_part, "test path") {
                return Err(err);
            }
        } else if program == "py_module" {
            if a.starts_with('-') {
                return Err(format!(
                    "unsupported proof command: {tok:?} passes unsupported option {a:?} to '-m {mod_name}'; fail-closed (#750 C19)"
                ));
            }
            if let Some(err) = check_rel_operand(tok, a, "operand") {
                return Err(err);
            }
            staged.push(a.clone());
        } else if program == "grep" && !a.starts_with('-') {
            grep_pos.push(a.clone());
        }
        i += 1;
    }
    if i < rest.len() && rest[i] == "--" {
        if program == "pytest" {
            for post_a in &rest[i + 1..] {
                let p_part = post_a.split("::").next().unwrap_or(post_a);
                if let Some(err) = check_rel_operand(tok, p_part, "test path") {
                    return Err(err);
                }
            }
        } else if program == "py_module" {
            for post_a in &rest[i + 1..] {
                if let Some(err) = check_rel_operand(tok, post_a, "operand") {
                    return Err(err);
                }
                staged.push(post_a.clone());
            }
        } else if program == "grep" {
            grep_pos.extend(rest[i + 1..].iter().cloned());
        }
    }
    if program == "grep" {
        let file_ops = if saw_grep_pat {
            &grep_pos[..]
        } else if !grep_pos.is_empty() {
            &grep_pos[1..]
        } else {
            &[]
        };
        for g_file in file_ops {
            if let Some(err) = check_rel_operand(tok, g_file, "file") {
                return Err(err);
            }
        }
    }
    Ok(staged)
}

pub fn unwrap_nc_indexed(
    argv: &[String],
    check_target_operands: bool,
) -> Result<Vec<(usize, String)>, String> {
    let mut indexed = Vec::new();
    let mut idx = 0usize;
    while idx < argv.len() {
        let tok = &argv[idx];
        let name = basename_of(tok);
        if tok.starts_with('-') || name.starts_with('-') {
            return Err(format!(
                "proof executable {tok:?} starts with '-', triggering login-shell startup or ambiguous option dispatch; fail-closed (#750 C19)"
            ));
        }
        if is_mux_exe(&name) {
            return Err(format!(
                "proof executable {tok:?} multiplexes inner commands whose targets cannot be statically pinned; fail-closed (#750 C19)"
            ));
        }
        indexed.push((idx, tok.clone()));
        let rest = &argv[idx + 1..];
        if is_shell_name(&name) {
            let _ = parse_shell_script_operand(tok, rest)?;
            break;
        }
        idx += 1;
        if name == "env" || name == "genv" {
            while idx < argv.len() {
                let a = &argv[idx];
                if a == "--" {
                    idx += 1;
                    break;
                }
                if matches!(a.as_str(), "-" | "-i" | "--ignore-environment") {
                    return Err(
                        "env -i/--ignore-environment alters PATH lookup context; fail-closed (#750 C19)"
                            .to_string(),
                    );
                }
                if !a.starts_with('-') {
                    break;
                }
                if matches!(a.as_str(), "-S" | "--split-string") || a.starts_with("--split-string=")
                {
                    return Err(
                        "env -S/--split-string performs runtime word splitting; fail-closed (#750 C19)"
                            .to_string(),
                    );
                }
                if matches!(a.as_str(), "-C" | "--chdir") || a.starts_with("--chdir=") {
                    return Err(
                        "env -C/--chdir alters working-directory lookup context; fail-closed (#750 C19)"
                            .to_string(),
                    );
                }
                if matches!(a.as_str(), "-P" | "--default-path") || a.starts_with("--default-path=")
                {
                    return Err(
                        "env -P/--default-path alters PATH lookup context; fail-closed (#750 C19)"
                            .to_string(),
                    );
                }
                if matches!(a.as_str(), "-u" | "--unset") || a.starts_with("--unset=") {
                    let uvar = if let Some(v) = a.strip_prefix("--unset=") {
                        idx += 1;
                        v.to_string()
                    } else if idx + 1 < argv.len() {
                        let v = argv[idx + 1].clone();
                        idx += 2;
                        v
                    } else {
                        return Err(
                            "env -u/--unset missing variable name; fail-closed (#750 C19)"
                                .to_string(),
                        );
                    };
                    if uvar.is_empty() || env_var_forbidden(&uvar) {
                        return Err(format!(
                            "env unset {uvar:?} alters executable lookup context; fail-closed (#750 C19)"
                        ));
                    }
                    continue;
                }
                if a.starts_with("--") {
                    if matches!(a.as_str(), "--null" | "--debug" | "--list-signal-handling")
                        || a.starts_with("--block-signal")
                        || a.starts_with("--default-signal")
                        || a.starts_with("--ignore-signal")
                    {
                        idx += 1;
                        continue;
                    }
                    return Err(format!(
                        "env option {a:?} is unsupported; fail-closed (#750 C19)"
                    ));
                }
                let short: Vec<char> = a[1..].chars().collect();
                let mut si = 0usize;
                let mut consumed_next = false;
                while si < short.len() {
                    let ch = short[si];
                    if ch == '0' || ch == 'v' {
                        si += 1;
                        continue;
                    }
                    if ch == 'i' {
                        return Err(
                            "env -i alters PATH lookup context; fail-closed (#750 C19)".to_string()
                        );
                    }
                    if matches!(ch, 'S' | 'C' | 'P') {
                        return Err(format!(
                            "env -{ch} alters execution/lookup context; fail-closed (#750 C19)"
                        ));
                    }
                    if ch == 'u' {
                        let rem: String = short[si + 1..].iter().collect();
                        let uvar = if !rem.is_empty() {
                            rem
                        } else if idx + 1 < argv.len() {
                            consumed_next = true;
                            argv[idx + 1].clone()
                        } else {
                            return Err(
                                "env -u missing variable name; fail-closed (#750 C19)".to_string()
                            );
                        };
                        if uvar.is_empty() || env_var_forbidden(&uvar) {
                            return Err(format!(
                                "env -u {uvar:?} alters executable lookup context; fail-closed (#750 C19)"
                            ));
                        }
                        break;
                    }
                    return Err(format!(
                        "env option -{ch} is unsupported; fail-closed (#750 C19)"
                    ));
                }
                idx += if consumed_next { 2 } else { 1 };
            }
            while idx < argv.len() && argv[idx].contains('=') {
                let lhs = argv[idx].split('=').next().unwrap_or("");
                if lhs.is_empty() || env_var_forbidden(lhs) {
                    return Err(format!(
                        "env assignment {lhs:?} alters executable lookup context; fail-closed (#750 C19)"
                    ));
                }
                idx += 1;
            }
            if idx >= argv.len() {
                return Err(
                    "env wrapper has no target proof command; fail-closed (#750 C19)".to_string(),
                );
            }
        } else if name == "command" {
            if idx < argv.len() && argv[idx].starts_with('-') && argv[idx].len() > 1 {
                if argv[idx] == "--" {
                    idx += 1;
                } else {
                    return Err(format!(
                        "command option {:?} alters lookup/execution; fail-closed (#750 C19)",
                        argv[idx]
                    ));
                }
            }
            if idx >= argv.len() {
                return Err(
                    "command wrapper has no target proof command; fail-closed (#750 C19)"
                        .to_string(),
                );
            }
        } else if name == "nohup" || name == "gnohup" {
            if idx < argv.len() && argv[idx].starts_with('-') && argv[idx].len() > 1 {
                if argv[idx] == "--" {
                    idx += 1;
                } else {
                    return Err(format!(
                        "nohup option {:?} is unsupported; fail-closed (#750 C19)",
                        argv[idx]
                    ));
                }
            }
            if idx >= argv.len() {
                return Err(
                    "nohup wrapper has no target proof command; fail-closed (#750 C19)".to_string(),
                );
            }
        } else if name == "nice" || name == "gnice" {
            while idx < argv.len() && argv[idx].starts_with('-') && argv[idx].len() > 1 {
                let opt = &argv[idx];
                if opt == "--" {
                    idx += 1;
                    break;
                }
                if matches!(opt.as_str(), "-n" | "--adjustment") {
                    if idx + 1 >= argv.len() {
                        return Err(format!(
                            "nice {opt} missing adjustment value; fail-closed (#750 C19)"
                        ));
                    }
                    idx += 2;
                } else if opt.starts_with("-n")
                    || opt.starts_with("--adjustment=")
                    || opt
                        .strip_prefix("--")
                        .or_else(|| opt.strip_prefix('-'))
                        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                {
                    idx += 1;
                } else {
                    return Err(format!(
                        "nice option {opt:?} is unsupported; fail-closed (#750 C19)"
                    ));
                }
            }
            if idx >= argv.len() {
                return Err(
                    "nice wrapper has no target proof command; fail-closed (#750 C19)".to_string(),
                );
            }
        } else if name == "timeout" || name == "gtimeout" {
            while idx < argv.len() && argv[idx].starts_with('-') && argv[idx].len() > 1 {
                let opt = &argv[idx];
                if opt == "--" {
                    idx += 1;
                    break;
                }
                if matches!(opt.as_str(), "-k" | "--kill-after" | "-s" | "--signal") {
                    if idx + 1 >= argv.len() {
                        return Err(format!(
                            "timeout {opt} missing argument; fail-closed (#750 C19)"
                        ));
                    }
                    idx += 2;
                } else if matches!(
                    opt.as_str(),
                    "-v" | "--verbose" | "--foreground" | "--preserve-status"
                ) || opt.starts_with("-k")
                    || opt.starts_with("--kill-after=")
                    || opt.starts_with("-s")
                    || opt.starts_with("--signal=")
                {
                    idx += 1;
                } else if !opt.starts_with("--")
                    && (opt.ends_with('k') || opt.ends_with('s'))
                    && opt[1..opt.len() - 1].chars().all(|c| c == 'v')
                {
                    if idx + 1 >= argv.len() {
                        return Err(format!(
                            "timeout {opt} missing argument; fail-closed (#750 C19)"
                        ));
                    }
                    idx += 2;
                } else {
                    return Err(format!(
                        "timeout option {opt:?} is unsupported; fail-closed (#750 C19)"
                    ));
                }
            }
            if idx + 1 >= argv.len() {
                return Err(
                    "timeout wrapper missing duration or target proof command; fail-closed (#750 C19)"
                        .to_string(),
                );
            }
            idx += 1; // duration operand
        } else {
            if check_target_operands {
                let _ = parse_target_operands(tok, rest)?;
            }
            break;
        }
    }
    Ok(indexed)
}

pub fn python_module_target(argv: &[String]) -> Option<String> {
    let indexed = unwrap_nc_indexed(argv, true).ok()?;
    let (target_idx, target_tok) = indexed.last()?;
    let tail = &argv[*target_idx + 1..];
    if !python_name_re().is_match(&basename_of(target_tok)) {
        return None;
    }
    let mut pi = 0usize;
    while pi < tail.len()
        && matches!(
            tail[pi].as_str(),
            "-B" | "-E" | "-I" | "-O" | "-OO" | "-s" | "-S" | "-u" | "-q"
        )
    {
        pi += 1;
    }
    let arg = tail.get(pi)?;
    if !arg.starts_with("-m") {
        return None;
    }
    let m = if arg == "-m" {
        tail.get(pi + 1).map(|s| s.as_str()).unwrap_or("")
    } else {
        &arg[2..]
    };
    if m.is_empty() || m == "pytest" || m == "unittest" {
        None
    } else {
        Some(m.to_string())
    }
}

pub fn staged_script_operands(argv: &[String]) -> Vec<String> {
    let Ok(indexed) = unwrap_nc_indexed(argv, true) else {
        return Vec::new();
    };
    let Some((target_idx, target_tok)) = indexed.last() else {
        return Vec::new();
    };
    let tail = &argv[*target_idx + 1..];
    if is_shell_name(&basename_of(target_tok)) {
        parse_shell_script_operand(target_tok, tail)
            .map(|s| vec![s])
            .unwrap_or_default()
    } else {
        parse_target_operands(target_tok, tail).unwrap_or_default()
    }
}

pub fn verify_staged_rel_file(repo_dir: &Path, rel_path: &str) -> Result<String, String> {
    let repo_real = fs::canonicalize(repo_dir).map_err(|e| {
        format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
    })?;
    let norm_rel = normpath_str(rel_path);
    if Path::new(rel_path).is_absolute()
        || norm_rel.is_empty()
        || norm_rel == "."
        || Path::new(&norm_rel)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "proof input {rel_path:?} escapes the staged commit; fail-closed (#750 C19)"
        ));
    }
    let mut cur = repo_real.clone();
    for part in Path::new(&norm_rel).components() {
        if matches!(part, Component::CurDir) {
            continue;
        }
        cur = cur.join(part.as_os_str());
        let lst = fs::symlink_metadata(&cur).map_err(|e| {
            format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
        })?;
        if lst.file_type().is_symlink() {
            cur = fs::canonicalize(&cur).map_err(|e| {
                format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
            })?;
            if cur != repo_real && !cur.starts_with(&repo_real) {
                return Err(format!(
                    "proof input {rel_path:?} resolves via symlink outside the staged commit; fail-closed (#750 C19)"
                ));
            }
        }
    }
    let final_real = fs::canonicalize(&cur).map_err(|e| {
        format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
    })?;
    let st = fs::metadata(&final_real).map_err(|e| {
        format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
    })?;
    let grp_oth_writable = {
        #[cfg(unix)]
        {
            (st.permissions().mode() & 0o022) != 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    if final_real == repo_real
        || !final_real.starts_with(&repo_real)
        || !st.is_file()
        || grp_oth_writable
    {
        return Err(format!(
            "proof input {rel_path:?} is missing, writable, or escapes the staged commit; fail-closed (#750 C19)"
        ));
    }
    let bytes = fs::read(&final_real).map_err(|e| {
        format!("proof input {rel_path:?} does not exist in staged commit ({e}); fail-closed (#750 C19)")
    })?;
    Ok(sha256_hex(&bytes))
}

fn shebang_arg_allowed(interp_names: &HashSet<String>, interp_arg: &str) -> bool {
    if interp_arg.is_empty() {
        return true;
    }
    if interp_names.iter().any(|n| python_name_re().is_match(n)) {
        return Regex::new(r"^-[BEIOPSsuq]+$")
            .expect("re")
            .is_match(interp_arg);
    }
    if interp_names.iter().any(|n| {
        Regex::new(r"^(?:sh|bash|dash|ash|ksh|mksh|yash)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
            .expect("re")
            .is_match(n)
    }) {
        return Regex::new(r"^-[abefhmnuvxBCEHP]+$")
            .expect("re")
            .is_match(interp_arg);
    }
    if interp_names.iter().any(|n| {
        Regex::new(r"^perl(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
            .expect("re")
            .is_match(n)
    }) {
        return Regex::new(r"^-[wTt]+$").expect("re").is_match(interp_arg);
    }
    if interp_names.iter().any(|n| {
        Regex::new(r"^(?:[gmnb]?awk|sed|[gs]sed)(?:[-.]?[0-9]+(?:\.[0-9]+)*)?$")
            .expect("re")
            .is_match(n)
    }) {
        return interp_arg == "-f";
    }
    false
}

fn verify_exec_file_and_shebang(
    resolved: &Path,
    label: &str,
    roots: &[PathBuf],
    search_path: &str,
    depth: usize,
) -> Result<Vec<ExecFileRec>, String> {
    if depth > 4 {
        return Err(format!(
            "proof executable {label:?} exceeds shebang nesting depth; fail-closed (#750 C19)"
        ));
    }
    let abs_path = abspath(resolved);
    let nodes = walk_nodes(&abs_path)
        .map_err(|e| format!("proof executable {label:?} cannot be verified ({e})"))?;
    let real = fs::canonicalize(&abs_path)
        .map_err(|e| format!("proof executable {label:?} cannot be verified ({e})"))?;
    let st = fs::metadata(&real)
        .map_err(|e| format!("proof executable {label:?} cannot be verified ({e})"))?;
    let is_exec = {
        #[cfg(unix)]
        {
            st.is_file() && (st.permissions().mode() & 0o111) != 0
        }
        #[cfg(not(unix))]
        {
            st.is_file()
        }
    };
    if !is_exec {
        return Err(format!(
            "proof executable {label:?} is not an executable regular file ({})",
            real.display()
        ));
    }
    #[cfg(unix)]
    {
        if (st.permissions().mode() & 0o022) != 0 {
            return Err(format!(
                "proof executable {label:?} ({}) is group- or world-writable; fail-closed (#750 C19)",
                real.display()
            ));
        }
        for (n, nst) in &nodes {
            if nst.file_type().is_symlink() {
                continue;
            }
            let mode = nst.permissions().mode();
            let sticky_dir = nst.is_dir() && (mode & 0o1000) != 0;
            if (mode & 0o022) != 0 && !sticky_dir {
                return Err(format!(
                    "proof executable {label:?} resolves through writable node {}; fail-closed (#750 C19)",
                    n.display()
                ));
            }
        }
    }
    let raw_bytes = fs::read(&real)
        .map_err(|e| format!("proof executable {label:?} cannot be verified ({e})"))?;
    let digest = sha256_hex(&raw_bytes);

    for r in roots {
        if real == *r
            || real.starts_with(r)
            || nodes.iter().any(|(n, _)| n == r || n.starts_with(r))
        {
            return Err(format!(
                "proof executable {label:?} resolves inside the repository worktree ({}); fail-closed",
                real.display()
            ));
        }
    }

    let hops: Vec<HopSig> = nodes
        .iter()
        .map(|(n, nst)| {
            #[cfg(unix)]
            {
                HopSig {
                    path: n.display().to_string(),
                    mode_fmt: nst.mode() & 0o170000,
                    dev: nst.dev(),
                    ino: nst.ino(),
                }
            }
            #[cfg(not(unix))]
            {
                HopSig {
                    path: n.display().to_string(),
                    mode_fmt: if nst.is_dir() { 0o040000 } else { 0o100000 },
                    dev: 0,
                    ino: 0,
                }
            }
        })
        .collect();
    let self_rec = {
        #[cfg(unix)]
        {
            ExecFileRec {
                abs_path: abs_path.display().to_string(),
                real_path: real.display().to_string(),
                dev: st.dev(),
                ino: st.ino(),
                size: st.size(),
                mtime_ns: (st.mtime() as i128) * 1_000_000_000 + (st.mtime_nsec() as i128),
                digest,
                hops,
            }
        }
        #[cfg(not(unix))]
        {
            ExecFileRec {
                abs_path: abs_path.display().to_string(),
                real_path: real.display().to_string(),
                dev: 0,
                ino: 0,
                size: st.len(),
                mtime_ns: 0,
                digest,
                hops,
            }
        }
    };

    if !raw_bytes.starts_with(b"#!") {
        return Ok(vec![self_rec]);
    }
    let nl = raw_bytes.iter().position(|&b| b == b'\n');
    let first_line = match nl {
        Some(pos) => &raw_bytes[2..pos],
        None => &raw_bytes[2..],
    };
    if first_line.contains(&b'\r')
        || first_line.contains(&0)
        || (nl.is_none() && raw_bytes.len() > 255)
        || first_line.len() > 253
    {
        return Err(format!(
            "proof executable {label:?} has malformed or CR-terminated shebang; fail-closed (#750 C19)"
        ));
    }
    let line_str = String::from_utf8_lossy(first_line)
        .trim_matches([' ', '\t'])
        .to_string();
    let (interp, interp_arg) = match line_str.find([' ', '\t']) {
        Some(pos) => (
            line_str[..pos].to_string(),
            line_str[pos..].trim_matches([' ', '\t']).to_string(),
        ),
        None => (line_str, String::new()),
    };
    if interp.is_empty() || !interp.starts_with('/') {
        return Err(format!(
            "proof executable {label:?} uses relative or empty shebang interpreter {interp:?}; fail-closed (#750 C19)"
        ));
    }
    let sub_chain = verify_exec_file_and_shebang(
        Path::new(&interp),
        &format!("{label}#!{interp}"),
        roots,
        search_path,
        depth + 1,
    )?;
    let i_base = basename_of(&interp);
    let i_real_base = basename_of(&sub_chain[0].real_path);
    let eff_i_real_base =
        if multicall_box_re().is_match(&i_real_base) && !multicall_box_re().is_match(&i_base) {
            i_base.clone()
        } else {
            i_real_base
        };
    let mut interp_names = HashSet::new();
    interp_names.insert(i_base.clone());
    interp_names.insert(eff_i_real_base.clone());
    let wrap_set = [
        "nice", "gnice", "timeout", "gtimeout", "nohup", "gnohup", "command", "builtin",
    ];
    if is_mux_exe(&i_base)
        || is_mux_exe(&eff_i_real_base)
        || interp_names.iter().any(|n| wrap_set.contains(&n.as_str()))
        || interp_names.iter().any(|n| csh_tcsh_re().is_match(n))
        || (i_base != "sh" && interp_names.iter().any(|n| rzsh_re().is_match(n)))
    {
        return Err(format!(
            "proof executable {label:?} uses multiplexer or wrapper shebang {interp:?}; fail-closed (#750 C19)"
        ));
    }
    if interp_names.contains("env") || interp_names.contains("genv") {
        if interp_arg.is_empty()
            || interp_arg.starts_with('-')
            || interp_arg.contains('=')
            || interp_arg.contains(' ')
            || interp_arg.contains('\t')
        {
            return Err(format!(
                "proof executable {label:?} shebang env argument {interp_arg:?} alters lookup or splits options; fail-closed (#750 C19)"
            ));
        }
        if interp_arg.contains('/') && !Path::new(&interp_arg).is_absolute() {
            return Err(format!(
                "proof executable {label:?} uses relative shebang env target {interp_arg:?}; fail-closed (#750 C19)"
            ));
        }
        let env_resolved = if Path::new(&interp_arg).is_absolute() {
            PathBuf::from(&interp_arg)
        } else {
            match which_in(&interp_arg, Some(search_path)) {
                Some(p) => p,
                None => {
                    return Err(format!(
                        "proof executable {label:?} shebang env target {interp_arg:?} cannot be resolved on the scrubbed PATH; fail-closed (#750 C19)"
                    ));
                }
            }
        };
        let env_chain = verify_exec_file_and_shebang(
            &env_resolved,
            &format!("{label}#!env:{interp_arg}"),
            roots,
            search_path,
            depth + 1,
        )?;
        let e_base = basename_of(&interp_arg);
        let e_real_base = basename_of(&env_chain[0].real_path);
        let eff_e_real_base =
            if multicall_box_re().is_match(&e_real_base) && !multicall_box_re().is_match(&e_base) {
                e_base.clone()
            } else {
                e_real_base
            };
        let mut e_names = HashSet::new();
        e_names.insert(e_base.clone());
        e_names.insert(eff_e_real_base.clone());
        let env_wrap_set = [
            "env", "genv", "nice", "gnice", "timeout", "gtimeout", "nohup", "gnohup", "command",
            "builtin",
        ];
        if is_mux_exe(&e_base)
            || is_mux_exe(&eff_e_real_base)
            || e_names.iter().any(|n| env_wrap_set.contains(&n.as_str()))
            || e_names.iter().any(|n| csh_tcsh_re().is_match(n))
            || (e_base != "sh" && e_names.iter().any(|n| rzsh_re().is_match(n)))
        {
            return Err(format!(
                "proof executable {label:?} shebang env target {interp_arg:?} resolves to multiplexer or wrapper; fail-closed (#750 C19)"
            ));
        }
        let mut out = vec![self_rec];
        out.extend(sub_chain);
        out.extend(env_chain);
        return Ok(out);
    }
    if !interp_arg.is_empty() && !shebang_arg_allowed(&interp_names, &interp_arg) {
        return Err(format!(
            "proof executable {label:?} shebang option {interp_arg:?} cannot be statically pinned; fail-closed (#750 C19)"
        ));
    }
    let mut out = vec![self_rec];
    out.extend(sub_chain);
    Ok(out)
}

pub fn walk_nodes(path: &Path) -> Result<Vec<(PathBuf, fs::Metadata)>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk_nodes_rec(path, &mut seen, &mut out)?;
    Ok(out)
}

fn walk_nodes_rec(
    path: &Path,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<(PathBuf, fs::Metadata)>,
) -> Result<(), String> {
    let comps: Vec<Component<'_>> = path.components().collect();
    if comps.is_empty() {
        return Err("empty path".to_string());
    }
    let mut cur = PathBuf::from(comps[0].as_os_str());
    let st0 = fs::symlink_metadata(&cur).map_err(|e| e.to_string())?;
    out.push((cur.clone(), st0));
    for (idx, comp) in comps[1..].iter().enumerate() {
        let i = idx + 1;
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                cur.pop();
            }
            other => cur.push(other.as_os_str()),
        }
        let st = fs::symlink_metadata(&cur).map_err(|e| e.to_string())?;
        let is_link = st.file_type().is_symlink();
        out.push((cur.clone(), st));
        if is_link {
            if !seen.insert(cur.clone()) || seen.len() >= 40 {
                return Err(format!(
                    "symlink loop or too many hops at {}",
                    cur.display()
                ));
            }
            let target = fs::read_link(&cur).map_err(|e| e.to_string())?;
            let mut next = if target.is_absolute() {
                target
            } else {
                cur.parent().unwrap_or_else(|| Path::new("/")).join(target)
            };
            for rem in &comps[i + 1..] {
                next.push(rem.as_os_str());
            }
            return walk_nodes_rec(&next, seen, out);
        }
    }
    Ok(())
}

fn worker_controls(node: &Path, st: &fs::Metadata) -> bool {
    if st.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        if st.uid() == uid {
            return true;
        }
        let mode = st.mode();
        if (mode & 0o002) != 0 {
            return true;
        }
        if (mode & 0o020) != 0 {
            let egid = unsafe { libc::getegid() };
            if st.gid() == egid || process_groups().contains(&st.gid()) {
                return true;
            }
        }
        if let Ok(cstr) = std::ffi::CString::new(node.as_os_str().as_bytes()) {
            if unsafe { libc::access(cstr.as_ptr(), libc::W_OK) } == 0 {
                return true;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = (node, st);
        false
    }
}

#[cfg(unix)]
fn process_groups() -> Vec<u32> {
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return Vec::new();
    }
    let mut gids = vec![0 as libc::gid_t; n as usize];
    let got = unsafe { libc::getgroups(n, gids.as_mut_ptr()) };
    if got <= 0 {
        return Vec::new();
    }
    gids.truncate(got as usize);
    gids
}

pub fn fs_git_toplevel(start: &Path) -> Option<PathBuf> {
    let mut cur = fs::canonicalize(start).ok()?;
    loop {
        if fs::symlink_metadata(cur.join(".git")).is_ok() {
            return Some(cur);
        }
        let parent = cur.parent()?;
        if parent == cur {
            return None;
        }
        cur = parent.to_path_buf();
    }
}

/// Non-strict canonicalize matching Python `Path.resolve(strict=False)`.
pub fn resolve_non_strict(path: &Path) -> PathBuf {
    let abs = abspath(path);
    let mut existing = abs.as_path();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        if let Ok(canon) = fs::canonicalize(existing) {
            let mut out = canon;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(p), Some(name)) => {
                tail.push(name.to_os_string());
                existing = p;
            }
            _ => return abs,
        }
    }
}

fn split_words_str(s: &str) -> Vec<String> {
    shlex_split(s, false).unwrap_or_else(|_| s.split_whitespace().map(|x| x.to_string()).collect())
}

fn words_from_value(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        Value::String(s) => split_words_str(s),
        _ => Vec::new(),
    }
}

fn words_from_toml(v: &toml::Value) -> Vec<String> {
    match v {
        toml::Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        toml::Value::String(s) => split_words_str(s),
        _ => Vec::new(),
    }
}

fn parse_ini_pytest_sections(text: &str) -> Result<Vec<BTreeMap<String, String>>, String> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut cur_sec: Option<String> = None;
    let mut cur_key: Option<String> = None;
    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with(';') {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') && stripped.starts_with('[') {
            if !stripped.ends_with(']') {
                return Err(format!("malformed INI section header: {stripped}"));
            }
            let name = stripped[1..stripped.len() - 1].trim().to_string();
            cur_sec = Some(name.clone());
            cur_key = None;
            sections.entry(name).or_default();
            continue;
        }
        let Some(ref sec) = cur_sec else {
            return Err("INI file contains content outside a section header".to_string());
        };
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(ref k) = cur_key {
                let entry = sections.entry(sec.clone()).or_default();
                let prev = entry.entry(k.clone()).or_default();
                prev.push('\n');
                prev.push_str(stripped);
            }
            continue;
        }
        let (k, v) = if let Some((a, b)) = raw_line.split_once('=') {
            (a.trim().to_ascii_lowercase(), b.trim().to_string())
        } else if let Some((a, b)) = raw_line.split_once(':') {
            (a.trim().to_ascii_lowercase(), b.trim().to_string())
        } else {
            (raw_line.trim().to_ascii_lowercase(), String::new())
        };
        cur_key = Some(k.clone());
        sections.entry(sec.clone()).or_default().insert(k, v);
    }
    let mut out = Vec::new();
    for name in ["pytest", "tool:pytest"] {
        if let Some(m) = sections.get(name) {
            out.push(m.clone());
        }
    }
    Ok(out)
}

pub fn glob_to_regex(glob: &str) -> Result<String, String> {
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if i + 2 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' && chars[i + 2] == '/' {
            out.push_str("(?:.*/)?");
            i += 3;
        } else if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' {
            out.push_str(".*");
            i += 2;
        } else if matches!(ch, '?' | '*' | '+' | '@' | '!') && chars.get(i + 1) == Some(&'(') {
            let mut depth = 0i32;
            let mut j = i + 1;
            let mut alts = Vec::new();
            let mut start = i + 2;
            while j < chars.len() {
                if chars[j] == '(' {
                    depth += 1;
                } else if chars[j] == ')' {
                    depth -= 1;
                }
                if depth == 1 && chars[j] == '|' {
                    let s: String = chars[start..j].iter().collect();
                    alts.push(s);
                    start = j + 1;
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth != 0 {
                return Err(format!("unbalanced extglob in {glob:?}"));
            }
            let last_s: String = chars[start..j].iter().collect();
            alts.push(last_s);
            let body = if ch == '!' {
                "[^/]*".to_string()
            } else {
                let mut rendered = Vec::new();
                for a in alts {
                    rendered.push(glob_to_regex(&a)?);
                }
                rendered.join("|")
            };
            let suffix = match ch {
                '?' => "?",
                '*' => "*",
                '+' => "+",
                _ => "",
            };
            out.push_str(&format!("(?:{body}){suffix}"));
            i = j + 1;
        } else if ch == '{' {
            if let Some(rel_end) = chars[i..].iter().position(|&c| c == '}') {
                let j = i + rel_end;
                let inner: String = chars[i + 1..j].iter().collect();
                let mut rendered = Vec::new();
                for a in inner.split(',') {
                    rendered.push(glob_to_regex(a)?);
                }
                out.push_str(&format!("(?:{})", rendered.join("|")));
                i = j + 1;
            } else {
                out.push_str(&regex::escape("{"));
                i += 1;
            }
        } else if ch == '[' {
            if let Some(rel_end) = chars[i + 1..].iter().position(|&c| c == ']') {
                let j = i + 1 + rel_end;
                let mut cls: String = chars[i + 1..j].iter().collect();
                if let Some(rest) = cls.strip_prefix('!') {
                    cls = format!("^{rest}");
                }
                cls = cls.replace('\\', "\\\\");
                out.push_str(&format!("[{cls}]"));
                i = j + 1;
            } else {
                out.push_str(&regex::escape("["));
                i += 1;
            }
        } else if ch == '*' {
            out.push_str("[^/]*");
            i += 1;
        } else if ch == '?' {
            out.push_str("[^/]");
            i += 1;
        } else {
            out.push_str(&regex::escape(&ch.to_string()));
            i += 1;
        }
    }
    Ok(out)
}

pub fn unreplayable_tool(tool: &str, raw_art: Option<&[u8]>) -> bool {
    if tool == "revert" || tool == "hand" {
        return false;
    }
    let Some(bytes) = raw_art else {
        return true;
    };
    let text = String::from_utf8_lossy(bytes);
    extract_diff(&text).is_none()
}

pub fn is_valid_hex40(s: &str) -> bool {
    is_hex40(s)
}
