//! Guard rules evaluator (`D`, `G`, `Y`, `N` records) ported from `runtime/scripts/deny-hook.sh`.
//!
//! Evaluates:
//! - Hard denies (`D`): brace refusal, `gh alias` refusal, `awk -f/-E` refusal, and git config/alias laundering.
//! - Self-guard (`G`): writes/deletes/mode-changes aimed at hook configs, `.orca/` trust anchors, or `deny-hook`.
//! - Root-wipe (`Y`): class-level recursive delete of `/` or `$HOME`.
//! - Parsed Never-list (`N`): history-discarding git, `gh secret`/`repo delete`, recursive `rm`,
//!   archive/patch extraction over guard dirs, and network fetch-and-run.

use crate::shell_parse;
use crate::shlex_util;
use crate::types::{GuardReport, HookConfig, ParsedPayload, QNL, UNSPLIT_SENTINEL};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

const SUB_MARK: &str = "__orca_substitution__";

const GH_OPERAND_FLAGS: &[&str] = &["-R", "--repo", "--hostname"];

const GIT_GLOBAL_ARG: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

const GIT_CONFIG_READS: &[&str] = &[
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "-l",
    "--list",
    "--unset",
    "--unset-all",
    "--remove-section",
    "--rename-section",
    "-e",
    "--edit",
    "--show-origin",
    "--show-scope",
    "--name-only",
    "--get-colorbool",
];

const GIT_CONFIG_OPERAND: &[&str] = &["-f", "--file", "--blob", "--default", "--type"];

const GIT_EXEC_CONFIG_EXACT: &[&str] = &[
    "core.fsmonitor",
    "core.pager",
    "core.sshcommand",
    "core.hookspath",
    "core.editor",
    "core.askpass",
    "credential.helper",
    "diff.external",
    "core.alternaterefscommand",
    "gpg.program",
    "protocol.allow",
];

const GUARD_SAMPLES: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".openhands/hooks.json",
    ".agents/plugins/orca-deny-hook/hooks/hooks.json",
    ".opencode/plugin/orca-deny-hook.ts",
    ".open-fleet/hooks/deny-hook.sh",
    ".open-fleet/bridges/omp_pi_deny_bridge.ts",
    ".crush/crush.json",
    ".crush-orca-ro/crush.json",
    ".hermes-open-fleet/config.yaml",
    ".orca/human-grant-pubkey",
    ".orca/dispatch-pubkey",
];

const GUARD_DIRS_REL: &[&str] = &[
    ".agents/plugins/orca-deny-hook/hooks",
    ".claude",
    ".codex",
    ".crush",
    ".crush-orca-ro",
    ".hermes-open-fleet",
    ".open-fleet/bridges",
    ".open-fleet/hooks",
    ".opencode/plugin",
    ".openhands",
    ".orca",
];

const GUARD_BASENAMES: &[&str] = &[
    "settings.json",
    "settings.local.json",
    "hooks.json",
    "orca-deny-hook.ts",
    "deny-hook.sh",
    "omp_pi_deny_bridge.ts",
    "crush.json",
    "human-grant-pubkey",
    "dispatch-pubkey",
];

const RSYNC_ARG: &[&str] = &[
    "-e",
    "--rsh",
    "-f",
    "--filter",
    "--exclude",
    "--include",
    "--exclude-from",
    "--include-from",
    "--files-from",
    "-T",
    "--temp-dir",
    "-B",
    "--block-size",
    "-M",
    "--remote-option",
    "--log-file",
    "--out-format",
    "--partial-dir",
    "--backup-dir",
    "--suffix",
    "--compare-dest",
    "--copy-dest",
    "--link-dest",
    "--chmod",
    "--chown",
    "--password-file",
    "--port",
    "--timeout",
    "--bwlimit",
    "--max-size",
    "--min-size",
    "--rsync-path",
    "--address",
    "-@",
    "--modify-window",
    "--info",
    "--debug",
];

const FIND_NAME_TESTS: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
];

const FIND_UNPROVABLE: &[&str] = &["!", "-not", "-o", "-or", ",", "(", ")", "-regex", "-iregex"];

const WHOLE_TREE: &[&str] = &[".", "./", "./*", "*", ":/", ":/*", ":(top)", ":(top)."];

const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "hush",
];

const RUNNERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "fish", "csh", "tcsh",
    "source", ".", "eval", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "pwsh",
];

const BODY_LAUNCHERS: &[&str] = &[
    "su", "runuser", "flock", "script", "watch", "parallel", "ssh", "find", "fd", "fdfind", "entr",
    "repeat",
];

const PARALLEL_LONG: &[&str] = &[
    "--jobs",
    "--max-procs",
    "--sshlogin",
    "--sshloginfile",
    "--slf",
    "--arg-file",
    "--delimiter",
    "--eof",
    "--max-args",
    "--max-lines",
    "--max-chars",
    "--colsep",
    "--tmpdir",
    "--joblog",
    "--results",
    "--res",
    "--workdir",
    "--wd",
    "--timeout",
    "--delay",
    "--retries",
    "--env",
    "--halt",
    "--memfree",
    "--load",
    "--nice",
    "--tagstring",
    "--basefile",
    "--bf",
    "--return",
    "--transferfile",
    "--tf",
    "--sshdelay",
    "--termseq",
    "--limit",
    "--rpl",
    "--header",
    "--block",
    "--recstart",
    "--recend",
    "--compress-program",
    "--decompress-program",
    "--semaphorename",
    "--id",
];

const PARALLEL_SEPS: &[&str] = &[":::", "::::", ":::+", "::::+"];

const DIR_LONGS: &[&str] = &["--directory", "--cd", "--chdir"];

const TAR_TAKES: &str = "fCbLVXTIgG";

struct GuardRegexes {
    git_danger_push: Regex,
    git_exec_config: Regex,
    git_config_key_env: Regex,
    guard_in: Regex,
    guard_any: Regex,
    guard_rel: Regex,
    orca_dir: Regex,
    chmod_additive: Regex,
    chmod_minus_mode: Regex,
    url_scheme: Regex,
    short_end_t: Regex,
    short_glued_t: Regex,
    short_big_t: Regex,
    short_in_place: Regex,
    code_writes: Regex,
    code_literal: Regex,
    exec_call: Regex,
    sub_redir: Regex,
    coarse_write: Regex,
    sqlite_dot: Regex,
    sed_exec_line: Regex,
    parallel_ph: Regex,
    fd_short_exec: Regex,
    entr_flags: Regex,
    shell_short_flag: Regex,
    short_c_cluster: Regex,
    short_x_cluster: Regex,
    short_alpha_flag: Regex,
}

fn regexes() -> &'static GuardRegexes {
    static RE: OnceLock<GuardRegexes> = OnceLock::new();
    RE.get_or_init(|| {
        let guard_files = concat!(
            r"\.claude/settings[^/]*\.json|\.codex/hooks\.json|\.openhands/hooks\.json",
            r"|\.agents/plugins/orca-deny-hook(/.*)?|\.opencode/plugins?/orca-deny-hook\.ts",
            r"|\.crush/crush\.json|\.crush-orca-ro(/.*)?|\.hermes-open-fleet(/.*)?",
            r"|\.orca/human-grant-pubkey|\.orca/dispatch-pubkey",
        );
        let guard_dirs = concat!(
            r"\.claude|\.codex|\.openhands|\.agents|\.agents/plugins",
            r"|\.opencode|\.opencode/plugins?|\.crush",
        );
        GuardRegexes {
            git_danger_push: Regex::new(r"^remote\..+\.(mirror|push|prune)$")
                .expect("valid git_danger_push regex"),
            git_exec_config: Regex::new(concat!(
                r"^(?:pager\..+|credential\..+\.helper|diff\..+\.(?:command|textconv)",
                r"|filter\..+\.(?:clean|smudge|process)|merge\..+\.driver",
                r"|gpg\..+\.program|protocol\..+\.allow)$",
            ))
            .expect("valid git_exec_config regex"),
            git_config_key_env: Regex::new(r"^GIT_CONFIG_KEY_[0-9]+$")
                .expect("valid git_config_key_env regex"),
            guard_in: Regex::new(&format!(
                r"^({guard_files}|\.open-fleet(/.*)?|{guard_dirs})/?$"
            ))
            .expect("valid guard_in regex"),
            guard_any: Regex::new(&format!(
                r"(^|/)({guard_files}|\.open-fleet/(hooks|bridges)(/.*)?|{guard_dirs})/?$"
            ))
            .expect("valid guard_any regex"),
            guard_rel: Regex::new(&format!(
                r"(^|/)({guard_files}|\.open-fleet(/.*)?|{guard_dirs})/?$"
            ))
            .expect("valid guard_rel regex"),
            orca_dir: Regex::new(r"(^|/)\.orca/?$").expect("valid orca_dir regex"),
            chmod_additive: Regex::new(r"^[ugoa]*\+[rwxXst]*(,[ugoa]*\+[rwxXst]*)*$")
                .expect("valid chmod_additive regex"),
            chmod_minus_mode: Regex::new(r"^-[rwxXst]+$").expect("valid chmod_minus_mode regex"),
            url_scheme: Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").expect("valid url_scheme regex"),
            short_end_t: Regex::new(r"^-[A-Za-z]*t$").expect("valid short_end_t regex"),
            short_glued_t: Regex::new(r"^-[A-Za-z]*?t[^A-Za-z].*$")
                .expect("valid short_glued_t regex"),
            short_big_t: Regex::new(r"^-[A-Za-z]*T[A-Za-z]*$").expect("valid short_big_t regex"),
            short_in_place: Regex::new(r"^-[A-Za-z]*i\S*$").expect("valid short_in_place regex"),
            code_writes: Regex::new(concat!(
                r#"write|unlink|remove|rmtree|rmdir|rename|replace|chmod|chown|truncate"#,
                r#"|symlink|link|copy|move|system|popen|spawn|exec|subprocess|FileUtils"#,
                r#"|rmSync|>|open[^)]*["'][rbt]*[wax+]"#,
            ))
            .expect("valid code_writes regex"),
            code_literal: Regex::new(r#"(?s)"((?:[^"\\]|\\.)*)"|'([^']*)'"#)
                .expect("valid code_literal regex"),
            exec_call: Regex::new(concat!(
                r"(system|popen|spawn[A-Za-z]*|exec[A-Za-z]*|run|call",
                r"|check_output|check_call|Popen)[ \t]*\(",
            ))
            .expect("valid exec_call regex"),
            sub_redir: Regex::new(r#"<{1,3}[ \t]*"?__orca_substitution__"#)
                .expect("valid sub_redir regex"),
            coarse_write: Regex::new(r"(?:&>>?|>>|>\||>&|<>|>)[ \t]*([^ \t\n;&|<>()]+)")
                .expect("valid coarse_write regex"),
            sqlite_dot: Regex::new(r"^\s*\.(shell|system)\s+(.+)$")
                .expect("valid sqlite_dot regex"),
            sed_exec_line: Regex::new(r"^\s*(?:[0-9]+|\$|/(?:[^/\\]|\\.)*/|,)*\s*e\s+(\S.*)$")
                .expect("valid sed_exec_line regex"),
            parallel_ph: Regex::new(r"\{[0-9./#%]*\}").expect("valid parallel_ph regex"),
            fd_short_exec: Regex::new(r"^-[HIusigFalLp0q]*[xX]$")
                .expect("valid fd_short_exec regex"),
            entr_flags: Regex::new(r"^-[acdnprsz]+$").expect("valid entr_flags regex"),
            shell_short_flag: Regex::new(r"^[-+][A-Za-z]+$").expect("valid shell_short_flag regex"),
            short_c_cluster: Regex::new(r"^-[A-Za-z]*c$").expect("valid short_c_cluster regex"),
            short_x_cluster: Regex::new(r"^-[A-Za-z]*x[A-Za-z]*$")
                .expect("valid short_x_cluster regex"),
            short_alpha_flag: Regex::new(r"^-[A-Za-z]+$").expect("valid short_alpha_flag regex"),
        }
    })
}

fn guard_seg_canon() -> &'static HashMap<String, &'static str> {
    static MAP: OnceLock<HashMap<String, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for g in GUARD_SAMPLES {
            for seg in g.split('/') {
                m.insert(seg.to_lowercase(), seg);
            }
        }
        m
    })
}

/// Evaluate all guard rules (`D`, `G`, `Y`, `N`) on a parsed Stage-1 payload.
pub fn evaluate(parsed: &ParsedPayload, cfg: &HookConfig) -> GuardReport {
    let mut report = GuardReport::default();

    // --- D: Hard denies ---
    if let Some(ref brace_msg) = parsed.brace_refusal {
        report.hard_denies.push(brace_msg.clone());
    }
    for view in &parsed.all_views {
        if let Some(why) = alias_refusal(&view.words, cfg) {
            report.hard_denies.push(why);
        }
    }
    for view in &parsed.all_views {
        if let Some(why) = awk_program_file(&view.words) {
            report.hard_denies.push(why);
        }
    }
    for view in &parsed.all_views {
        if let Some(why) = git_alias_laundering(&view.assigns, &view.words) {
            report.hard_denies.push(why);
        }
    }

    // --- G: Self-guard ---
    if matches!(
        parsed.norm_tool.as_str(),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
    ) {
        for p in &parsed.target_paths {
            if guarded(p, false, None, cfg) {
                report.guard_hits.push(p.clone());
            }
        }
    }
    for p in &parsed.heredoc_targets {
        if guarded(p, false, None, cfg) {
            report.guard_hits.push(p.clone());
        }
    }
    let mut seen_interp = BTreeSet::new();
    for code in &parsed.fed_interp {
        if seen_interp.insert(code.as_str()) {
            for (p, deleting) in code_guard_targets(code, 0, cfg) {
                if guarded(&p, deleting, None, cfg) {
                    report.guard_hits.push(p);
                }
            }
        }
    }
    let mut vcwd = cfg.cwd.to_string_lossy().into_owned();
    let mut vlost = false;
    for (args, writes) in &parsed.guard_segs {
        if let Some(cd) = cd_target(args) {
            if cd == "?" {
                vlost = true;
            } else {
                let expanded = expand_tilde(&cd, &cfg.home);
                vcwd = posix_normpath(&posix_join(&vcwd, &expanded));
            }
        }
        let mut targets: Vec<(String, bool)> = writes.iter().map(|w| (w.clone(), false)).collect();
        targets.extend(guard_targets(args, 0, cfg));
        for (p, deleting) in targets {
            let hit = guarded(&p, deleting, None, cfg)
                || guarded(&p, deleting, Some(&vcwd), cfg)
                || (vlost
                    && !p.starts_with(['/', '~'])
                    && GUARD_BASENAMES.contains(&posix_basename(p.trim_end_matches('/'))));
            if hit {
                report.guard_hits.push(p);
            }
        }
    }
    // Also judge non-top views and body redirects expanded by Stage 1 (e.g. variable heads
    // or brace-expanded quoted bodies that only Stage 1's _views/_body_texts saw).
    for view in &parsed.all_views {
        if !view.is_top {
            let mut targets: Vec<(String, bool)> =
                view.writes.iter().map(|w| (w.clone(), false)).collect();
            targets.extend(guard_targets(&view.words, 1, cfg));
            for (p, deleting) in targets {
                if guarded(&p, deleting, None, cfg) {
                    report.guard_hits.push(p);
                }
            }
        }
    }
    let mut seen_body = BTreeSet::new();
    for body_seg in &parsed.body_texts {
        if !seen_body.insert(body_seg.as_str()) {
            continue;
        }
        let body_writes = if let Some(raw) = body_seg.strip_prefix(UNSPLIT_SENTINEL) {
            coarse_write_targets(raw)
        } else {
            let (_args, writes) = shlex_util::tokenize_seg(body_seg);
            writes
        };
        for p in body_writes {
            if guarded(&p, false, None, cfg) {
                report.guard_hits.push(p);
            }
        }
    }

    // --- Y: Root-wipe ---
    report.root_wipe = parsed.all_views.iter().any(|v| root_wipe(&v.words));

    // --- N: Parsed Never-list ---
    for view in &parsed.all_views {
        if let Some(why) = never_git(&view.words) {
            report.never_reasons.push(why);
        }
    }
    for view in &parsed.all_views {
        if let Some(why) = never_gh(&view.words) {
            report.never_reasons.push(why);
        }
    }
    for view in &parsed.all_views {
        if let Some(why) = never_rm(&view.words) {
            report.never_reasons.push(why);
        }
    }
    for view in &parsed.all_views {
        if let Some(why) = extracts_over_guard(&view.words, cfg) {
            report.never_reasons.push(why);
        }
    }
    if fetch_runs(parsed) {
        report
            .never_reasons
            .push("Running a script fetched from the network in the same command.".to_string());
    }

    report
}

// -----------------------------------------------------------------------------
// Hard denies (D)
// -----------------------------------------------------------------------------

fn alias_refusal(ws: &[String], cfg: &HookConfig) -> Option<String> {
    if ws.is_empty() || cmd_base(&ws[0]) != "gh" {
        return None;
    }
    let (verb, _name, expansion, runs_in_shell) = shlex_util::gh_alias_detail(ws)?;
    if verb == "import" {
        return Some(
            "gh alias import loads alias expansions this hook cannot read; define each alias with gh alias set so its expansion is judged."
                .to_string(),
        );
    }
    if verb == "set" {
        let exp = expansion.as_deref().unwrap_or("");
        let body = if runs_in_shell {
            exp.to_string()
        } else {
            format!("gh {exp}")
        };
        if shell_parse::unreceipted_scope(&body, cfg) {
            return Some(
                "a gh alias whose expansion is an off-repo write runs it later; an outer egress receipt cannot cover a deferred send (rule 5). Put the receipt inside the alias, or run the write itself, receipted."
                    .to_string(),
            );
        }
    }
    None
}

fn is_awk(head: &str) -> bool {
    head == "original-awk"
        || (head.ends_with("awk")
            && head[..head.len() - 3]
                .bytes()
                .all(|b| b.is_ascii_lowercase()))
}

fn awk_sources(rest: &[String]) -> (Vec<String>, bool) {
    let mut progs = Vec::new();
    let mut saw_file = false;
    let mut seen_src = false;
    let mut i = 0usize;
    let takes = [
        "-v",
        "--assign",
        "-F",
        "--field-separator",
        "-i",
        "--include",
        "-l",
        "--load",
    ];
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            if i + 1 < rest.len() && !seen_src {
                progs.push(rest[i + 1].clone());
            }
            break;
        }
        if matches!(w, "-f" | "--file" | "-E" | "--exec") {
            saw_file = true;
            seen_src = true;
            i += 2;
            continue;
        }
        if w.starts_with("--file=") || w.starts_with("--exec=") {
            saw_file = true;
            seen_src = true;
            i += 1;
            continue;
        }
        if matches!(w, "-e" | "--source") && i + 1 < rest.len() {
            progs.push(rest[i + 1].clone());
            seen_src = true;
            i += 2;
            continue;
        }
        if let Some(val) = w.strip_prefix("--source=") {
            progs.push(val.to_string());
            seen_src = true;
            i += 1;
            continue;
        }
        if let Some(val) = w.strip_prefix("-e") {
            if !val.is_empty() && !w.starts_with("--") {
                progs.push(val.to_string());
                seen_src = true;
                i += 1;
                continue;
            }
        }
        if takes.contains(&w) {
            i += 2;
            continue;
        }
        if w.starts_with("--assign=")
            || w.starts_with("--field-separator=")
            || w.starts_with("--include=")
            || w.starts_with("--load=")
        {
            i += 1;
            continue;
        }
        if w.starts_with('-') && w.len() > 1 {
            if !w.starts_with("--") {
                for (byte_idx, flag) in w[1..].char_indices() {
                    if matches!(flag, 'd' | 'D' | 'L' | 'o' | 'p') {
                        break;
                    }
                    if matches!(flag, 'f' | 'E' | 'e' | 'F' | 'v' | 'W' | 'i' | 'l') {
                        let after = 1 + byte_idx + flag.len_utf8();
                        let mut operand = w[after..].to_string();
                        if operand.is_empty() && i + 1 < rest.len() {
                            i += 1;
                            operand = rest[i].clone();
                        }
                        if matches!(flag, 'f' | 'E') {
                            saw_file = true;
                            seen_src = true;
                        } else if flag == 'e' {
                            progs.push(operand);
                            seen_src = true;
                        }
                        break;
                    }
                }
            }
            i += 1;
            continue;
        }
        if !seen_src {
            progs.push(w.to_string());
        }
        break;
    }
    (progs, saw_file)
}

fn awk_program_file(ws: &[String]) -> Option<String> {
    if ws.is_empty() {
        return None;
    }
    let (head, rest) = shlex_util::peel_busybox(cmd_base(&ws[0]), &ws[1..]);
    if !is_awk(&head) {
        return None;
    }
    if awk_sources(&rest).1 {
        return Some(
            "awk is given a program FILE (-f/-E) this hook cannot read, so the program it runs is unknown and may launch a refused command. Inline the program with -e, or run it where the sandbox is the boundary."
                .to_string(),
        );
    }
    None
}

fn git_config_key_reason(
    raw_key: &str,
    inline_val: Option<&str>,
    from_dash_c: bool,
) -> Option<String> {
    let key = raw_key
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_lowercase();
    if key.is_empty() {
        return None;
    }
    if key.starts_with("alias.") || key.contains(".alias.") {
        return Some(
            "a git alias defined in the command itself (-c alias.*, --config-env=alias.*, GIT_CONFIG_*) renames the subcommand this hook judges by name; run the real subcommand instead."
                .to_string(),
        );
    }
    let re = regexes();
    if re.git_danger_push.is_match(&key) {
        return Some(format!(
            "a destructive push config ({key}) via -c/--config-env/GIT_CONFIG_* can mirror, prune or force-push remote refs without flags; push named refs instead."
        ));
    }
    if key == "core.pager" && from_dash_c && matches!(inline_val, Some("" | "cat")) {
        return None;
    }
    if GIT_EXEC_CONFIG_EXACT.contains(&key.as_str()) || re.git_exec_config.is_match(&key) {
        return Some(format!(
            "a command-executing git config key ({key}) runs an arbitrary command outside the hook judgment boundary; do not set execution hooks inline."
        ));
    }
    None
}

fn git_alias_laundering(assigns: &[String], ws: &[String]) -> Option<String> {
    if ws.is_empty() || cmd_base(&ws[0]) != "git" {
        return None;
    }
    let re = regexes();
    let mut entries: Vec<(String, Option<String>, bool)> = Vec::new();
    for a in assigns {
        let (name, value) = match a.split_once('=') {
            Some((n, v)) => (n, v),
            None => (a.as_str(), ""),
        };
        if re.git_config_key_env.is_match(name) {
            entries.push((value.to_string(), None, false));
        } else if name == "GIT_CONFIG_PARAMETERS" {
            let items = shlex_util::shlex_split(value)
                .unwrap_or_else(|_| value.split_whitespace().map(String::from).collect());
            for item in items {
                let k = item.split_once('=').map_or(item.as_str(), |(k, _)| k);
                entries.push((k.to_string(), None, false));
            }
        }
    }
    let rest = &ws[1..];
    let mut i = 0usize;
    while i < rest.len() && rest[i].starts_with('-') && rest[i] != "-" {
        let w = rest[i].as_str();
        if w == "-c" && i + 1 < rest.len() {
            let next = rest[i + 1].as_str();
            let (k, v) = match next.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (next, None),
            };
            entries.push((k.to_string(), v, true));
        } else if w.starts_with("-c") && w.len() > 2 {
            let tail = &w[2..];
            let (k, v) = match tail.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (tail, None),
            };
            entries.push((k.to_string(), v, true));
        } else if w == "--config-env" && i + 1 < rest.len() {
            let next = rest[i + 1].as_str();
            let k = next.split_once('=').map_or(next, |(k, _)| k);
            entries.push((k.to_string(), None, false));
        } else if let Some(after) = w.strip_prefix("--config-env=") {
            let k = after.split_once('=').map_or(after, |(k, _)| k);
            entries.push((k.to_string(), None, false));
        }
        i += if GIT_GLOBAL_ARG.contains(&w) { 2 } else { 1 };
    }
    for (k, val, from_c) in &entries {
        if let Some(why) = git_config_key_reason(k, val.as_deref(), *from_c) {
            return Some(why);
        }
    }
    let sub = rest.get(i..).unwrap_or(&[]);
    if sub.first().map(String::as_str) != Some("config") {
        return None;
    }
    let mut operands: Vec<&str> = Vec::new();
    let mut j = 1usize;
    while j < sub.len() {
        let w = sub[j].as_str();
        if GIT_CONFIG_READS.contains(&w) {
            return None;
        }
        if GIT_CONFIG_OPERAND.contains(&w) {
            j += 2;
            continue;
        }
        if !w.starts_with('-') || w == "-" {
            operands.push(w);
        }
        j += 1;
    }
    let (cfg_key, cfg_val) = if operands.len() >= 3 && operands[0] == "set" {
        (Some(operands[1]), Some(operands[2]))
    } else if operands.len() >= 2 {
        (Some(operands[0]), Some(operands[1]))
    } else {
        (None, None)
    };
    if let Some(k) = cfg_key {
        if k.to_lowercase().starts_with("alias.") {
            return Some(
                "git config alias.* defines an alias that a later command runs under another name, past every rule here; run the real subcommand instead."
                    .to_string(),
            );
        }
        if let Some(why) = git_config_key_reason(k, cfg_val, true) {
            return Some(why);
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Self-guard (G)
// -----------------------------------------------------------------------------

fn glob_segments(op_segs: &[&str], sample_segs: &[&str], prefix_ok: bool) -> bool {
    if op_segs.len() > sample_segs.len() || (!prefix_ok && op_segs.len() != sample_segs.len()) {
        return false;
    }
    for (o, g) in op_segs.iter().zip(sample_segs.iter()) {
        if g.starts_with('.') && !o.starts_with('.') {
            return false;
        }
        if !shlex_util::fnmatchcase(g, o) {
            return false;
        }
    }
    true
}

fn fold_guard_case(p: &str) -> String {
    let map = guard_seg_canon();
    p.split('/')
        .map(|seg| map.get(&seg.to_lowercase()).copied().unwrap_or(seg))
        .collect::<Vec<_>>()
        .join("/")
}

fn guarded(p: &str, deleting: bool, base: Option<&str>, cfg: &HookConfig) -> bool {
    if p.is_empty() {
        return false;
    }
    let folded = fold_guard_case(p);
    if folded != p && guarded_exact(&folded, deleting, base, cfg) {
        return true;
    }
    guarded_exact(p, deleting, base, cfg)
}

fn guarded_exact(p: &str, deleting: bool, base: Option<&str>, cfg: &HookConfig) -> bool {
    if p.is_empty() {
        return false;
    }
    let re = regexes();
    let expanded = expand_tilde(p, &cfg.home);
    let norm = posix_normpath(&expanded);
    let absn = if norm.starts_with('/') {
        norm.clone()
    } else {
        let base_dir = base
            .map(String::from)
            .unwrap_or_else(|| cfg.cwd.to_string_lossy().into_owned());
        posix_normpath(&posix_join(&base_dir, &norm))
    };
    let real = posix_realpath(&absn, &cfg.cwd);
    let groot = cfg.groot.to_string_lossy();
    let groot_prefix = format!("{}/", groot.trim_end_matches('/'));

    for cand in [absn.as_str(), real.as_str()] {
        if cand == groot.as_ref() || cand.starts_with(&groot_prefix) {
            let rel = if cand == groot.as_ref() {
                ""
            } else {
                &cand[groot_prefix.len()..]
            };
            if re.guard_in.is_match(rel) {
                return true;
            }
            let segs: Vec<&str> = rel.split('/').filter(|x| !x.is_empty()).collect();
            if deleting || rel.contains(['*', '?', '[']) {
                for sample in GUARD_SAMPLES {
                    let sample_segs: Vec<&str> = sample.split('/').collect();
                    if glob_segments(&segs, &sample_segs, deleting) {
                        return true;
                    }
                }
            }
        } else if re.guard_any.is_match(cand) || (deleting && re.orca_dir.is_match(cand)) {
            return true;
        }
    }
    if !norm.starts_with('/') && re.guard_rel.is_match(&norm) {
        return true;
    }
    let real_prefix = format!("{}/", real.trim_end_matches('/'));
    for me in &cfg.gself {
        let me_str = me.to_string_lossy();
        if real == me_str.as_ref() || (deleting && me_str.starts_with(&real_prefix)) {
            return true;
        }
    }
    deleting
        && cfg.unit_worktree.is_some()
        && (groot.as_ref() == real.as_str() || groot.starts_with(&real_prefix))
}

fn operands(rest: &[String], opt_arg: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut end = false;
    while i < rest.len() {
        let w = rest[i].as_str();
        if !end && w == "--" {
            end = true;
        } else if !end && w.starts_with('-') && w != "-" {
            if opt_arg.contains(&w) {
                i += 1;
            }
        } else {
            out.push(rest[i].clone());
        }
        i += 1;
    }
    out
}

fn git_sub(rest: &[String]) -> &[String] {
    let mut i = 0usize;
    while i < rest.len() && rest[i].starts_with('-') && rest[i] != "-" {
        i += if GIT_GLOBAL_ARG.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    rest.get(i..).unwrap_or(&[])
}

fn long_is(word: &str, names: &[&str]) -> bool {
    let Some(after) = word.strip_prefix("--") else {
        return false;
    };
    let name = after.split('=').next().unwrap_or("");
    !name.is_empty() && !name.starts_with("no-") && names.iter().any(|n| n.starts_with(name))
}

fn git_clean_takes_ignored(rest: &[String]) -> bool {
    let mut ignored = false;
    let mut dry = false;
    let mut i = 0usize;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            break;
        }
        if w.starts_with("--") {
            dry = dry || long_is(w, &["dry-run"]);
            if w == "--exclude" {
                i += 1;
            }
        } else if w.starts_with('-') && w.len() > 1 {
            let tail = &w[1..];
            for (byte_idx, ch) in tail.char_indices() {
                if ch == 'e' {
                    if byte_idx + ch.len_utf8() == tail.len() {
                        i += 1;
                    }
                    break;
                }
                if matches!(ch, 'x' | 'X') {
                    ignored = true;
                }
                if ch == 'n' {
                    dry = true;
                }
            }
        }
        i += 1;
    }
    ignored && !dry
}

fn git_clean_pathspecs(rest: &[String]) -> Vec<String> {
    let mut specs = Vec::new();
    let mut i = 0usize;
    let mut end = false;
    while i < rest.len() {
        let w = rest[i].as_str();
        if !end && w == "--" {
            end = true;
        } else if !end && w.starts_with("--") {
            if w == "--exclude" {
                i += 1;
            }
        } else if !end && w.starts_with('-') && w.len() > 1 {
            let tail = &w[1..];
            for (byte_idx, ch) in tail.char_indices() {
                if ch == 'e' {
                    if byte_idx + ch.len_utf8() == tail.len() {
                        i += 1;
                    }
                    break;
                }
            }
        } else {
            specs.push(rest[i].clone());
        }
        i += 1;
    }
    specs
}

fn git_stash_takes_untracked(rest: &[String]) -> bool {
    let ws: &[String] = match rest.first().map(String::as_str) {
        Some("push" | "save") => &rest[1..],
        Some(first) if !first.starts_with('-') => return false,
        _ => rest,
    };
    let mut i = 0usize;
    while i < ws.len() {
        let w = ws[i].as_str();
        if w == "--" {
            break;
        }
        if w.starts_with("--") {
            if long_is(w, &["all", "include-untracked"]) {
                return true;
            }
            if matches!(w, "--message" | "--pathspec-from-file") {
                i += 1;
            }
        } else if w.starts_with('-') && w.len() > 1 {
            let tail = &w[1..];
            for (byte_idx, ch) in tail.char_indices() {
                if ch == 'm' {
                    if byte_idx + ch.len_utf8() == tail.len() {
                        i += 1;
                    }
                    break;
                }
                if matches!(ch, 'u' | 'a') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

fn cd_target(words: &[String]) -> Option<String> {
    let (_assigns, ws) = shlex_util::command_words_with_assigns(words);
    if !matches!(ws.first().map(String::as_str), Some("cd" | "pushd")) {
        return None;
    }
    let target = ws[1..]
        .iter()
        .find(|w| !(w.starts_with('-') && w.as_str() != "-"))
        .map(String::as_str)
        .unwrap_or("~");
    if target == "-" || target.contains(['$', '`', '*', '?', '[']) {
        return Some("?".to_string());
    }
    Some(target.to_string())
}

fn attr_targets(head: &str, rest: &[String]) -> Vec<String> {
    let re = regexes();
    let mut ops = Vec::new();
    let mut end = false;
    let mut has_ref = false;
    for w in rest {
        let ws = w.as_str();
        if !end && ws == "--" {
            end = true;
        } else if !end && ws.starts_with("--reference") {
            has_ref = true;
        } else if !end
            && ws.starts_with('-')
            && ws.len() > 1
            && !(head == "chmod" && re.chmod_minus_mode.is_match(ws))
        {
            continue;
        } else {
            ops.push(w.clone());
        }
    }
    if has_ref {
        return ops;
    }
    if ops.is_empty() || (head == "chmod" && re.chmod_additive.is_match(&ops[0])) {
        return Vec::new();
    }
    ops[1..].to_vec()
}

fn sort_outputs(rest: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let takes_long = [
        "key",
        "field-separator",
        "buffer-size",
        "temporary-directory",
        "files0-from",
        "batch-size",
        "parallel",
        "compress-program",
        "random-source",
        "sort",
    ];
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            break;
        }
        if let Some(after) = w.strip_prefix("--") {
            let (name, eq_val) = match after.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (after, None),
            };
            if !name.is_empty() && "output".starts_with(name) {
                let val = match eq_val {
                    Some(v) => v.to_string(),
                    None if i + 1 < rest.len() => {
                        i += 1;
                        rest[i].clone()
                    }
                    None => String::new(),
                };
                out.push(val);
            } else if eq_val.is_none() && takes_long.contains(&name) {
                i += 1;
            }
        } else if w.starts_with('-') && w.len() > 1 {
            for (byte_idx, flag) in w[1..].char_indices() {
                if matches!(flag, 'o' | 'k' | 'S' | 't' | 'T') {
                    let after = 1 + byte_idx + flag.len_utf8();
                    let mut val = w[after..].to_string();
                    if val.is_empty() && i + 1 < rest.len() {
                        i += 1;
                        val = rest[i].clone();
                    }
                    if flag == 'o' {
                        out.push(val);
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    out
}

fn editor_targets(head: &str, rest: &[String]) -> Vec<String> {
    if matches!(head, "ed" | "red") {
        return operands(rest, &["-p"]);
    }
    let skip_opts = [
        "-c", "--cmd", "-S", "-u", "-U", "-i", "-s", "-T", "-t", "-q", "-w", "-W",
    ];
    let mut out: Vec<String> = operands(rest, &skip_opts)
        .into_iter()
        .filter(|w| !w.starts_with('+'))
        .collect();
    if rest.len() >= 2 {
        for i in 0..(rest.len() - 1) {
            if matches!(rest[i].as_str(), "-w" | "-W") {
                out.push(rest[i + 1].clone());
            }
        }
    }
    out
}

fn fetch_outputs(head: &str, rest: &[String]) -> Vec<String> {
    let (arg, out_flag, long_out) = if head == "curl" {
        ("oKdHuXAebcFTwxrmyYzCEPQtUD", 'o', "--output")
    } else {
        ("OoaiPtTwQUeBlARDXI", 'O', "--output-document")
    };
    let mut outs = Vec::new();
    let mut remote = false;
    let mut explicit = false;
    let mut i = 0usize;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w.starts_with("--") {
            let (name, eq_val) = match w.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (w, None),
            };
            if name == long_out {
                let val = match eq_val {
                    Some(v) => v.to_string(),
                    None if i + 1 < rest.len() => {
                        i += 1;
                        rest[i].clone()
                    }
                    None => String::new(),
                };
                outs.push(val);
                explicit = true;
            } else if matches!(name, "--remote-name" | "--remote-name-all") {
                remote = true;
            }
        } else if w.starts_with('-') && w.len() > 1 {
            for (byte_idx, flag) in w[1..].char_indices() {
                if head == "curl" && flag == 'O' {
                    remote = true;
                } else if arg.contains(flag) {
                    let after = 1 + byte_idx + flag.len_utf8();
                    let mut val = w[after..].to_string();
                    if val.is_empty() && i + 1 < rest.len() {
                        i += 1;
                        val = rest[i].clone();
                    }
                    if flag == out_flag {
                        outs.push(val);
                        explicit = true;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    if remote || (head == "wget" && !explicit) {
        let re = regexes();
        for u in rest {
            if re.url_scheme.is_match(u) {
                let stripped = u.split(['?', '#']).next().unwrap_or(u);
                let trimmed = stripped.trim_end_matches('/');
                let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
                outs.push(base.to_string());
            }
        }
    }
    outs.into_iter()
        .filter(|o| !o.is_empty() && o != "-")
        .collect()
}

fn find_split(rest: &[String]) -> (Vec<&str>, &[String]) {
    let mut i = 0usize;
    while i < rest.len() {
        let w = rest[i].as_str();
        if matches!(w, "-H" | "-L" | "-P") || w.starts_with("-D") || w.starts_with("-O") {
            i += if w == "-D" { 2 } else { 1 };
        } else {
            break;
        }
    }
    let mut roots = Vec::new();
    while i < rest.len() {
        let w = rest[i].as_str();
        if w.starts_with(['-', '(', '!', ')', ',']) {
            break;
        }
        roots.push(w);
        i += 1;
    }
    (roots, rest.get(i..).unwrap_or(&[]))
}

fn find_spots(root: &str, cfg: &HookConfig) -> Vec<(String, String)> {
    let cwd_str = cfg.cwd.to_string_lossy();
    let groot_str = cfg.groot.to_string_lossy();
    let expanded = expand_tilde(root, &cfg.home);
    let rabs = posix_normpath(&posix_join(&cwd_str, &expanded));
    let rabs_prefix = format!("{}/", rabs.trim_end_matches('/'));
    let mut out = Vec::new();

    let mut all_guards: Vec<String> = GUARD_SAMPLES.iter().map(|&s| s.to_string()).collect();
    for me in &cfg.gself {
        all_guards.push(me.to_string_lossy().into_owned());
    }
    for g in all_guards {
        let gabs = posix_normpath(&posix_join(&groot_str, &g));
        if gabs == rabs || gabs.starts_with(&rabs_prefix) {
            let shown = if gabs == rabs {
                root.to_string()
            } else {
                let rel = &gabs[rabs_prefix.len()..];
                format!("{}/{}", root.trim_end_matches('/'), rel)
            };
            out.push((shown, posix_basename(&gabs).to_string()));
        }
    }
    out
}

fn find_may_match(tests: &[String], shown: &str, name: &str) -> bool {
    if tests.iter().any(|t| FIND_UNPROVABLE.contains(&t.as_str())) {
        return true;
    }
    let mut i = 0usize;
    while i < tests.len() {
        let t = tests[i].as_str();
        if FIND_NAME_TESTS.contains(&t) && i + 1 < tests.len() {
            let subj = if matches!(t, "-name" | "-iname") {
                name
            } else {
                shown
            };
            let pat = tests[i + 1].as_str();
            let matched = if t.as_bytes().get(1) == Some(&b'i') {
                shlex_util::fnmatchcase(&subj.to_lowercase(), &pat.to_lowercase())
            } else {
                shlex_util::fnmatchcase(subj, pat)
            };
            if !matched {
                return false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    true
}

fn tar_info(rest: &[String]) -> (String, Vec<String>, Option<String>, Option<String>) {
    let mut letters = String::new();
    let mut longs = Vec::new();
    let mut pos = Vec::new();
    let mut pending: Vec<char> = Vec::new();
    let mut dashed: HashMap<String, String> = HashMap::new();
    let mut i = 0usize;

    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            pos.extend(rest[i + 1..].iter().cloned());
            break;
        }
        if let Some(after) = w.strip_prefix("--") {
            let (name, eq_val) = match after.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (after, None),
            };
            longs.push(name.to_string());
            if matches!(name, "file" | "directory") {
                if let Some(val) = eq_val {
                    dashed.insert(name.to_string(), val.to_string());
                } else if i + 1 < rest.len() {
                    dashed.insert(name.to_string(), rest[i + 1].clone());
                    i += 1;
                }
            }
            i += 1;
            continue;
        }
        if w.starts_with('-') && w.len() > 1 {
            let cluster = &w[1..];
            letters.push_str(cluster);
            if let Some((byte_idx, c)) =
                cluster.char_indices().find(|&(_, c)| TAR_TAKES.contains(c))
            {
                let glued = &cluster[byte_idx + c.len_utf8()..];
                if !glued.is_empty() {
                    dashed.insert(c.to_string(), glued.to_string());
                } else if i + 1 < rest.len() {
                    dashed.insert(c.to_string(), rest[i + 1].clone());
                    i += 1;
                }
            }
            i += 1;
            continue;
        }
        if letters.is_empty()
            && pos.is_empty()
            && !w.is_empty()
            && w.bytes().all(|b| b.is_ascii_alphabetic())
        {
            letters.push_str(w);
            pending = w.chars().filter(|&c| TAR_TAKES.contains(c)).collect();
            i += 1;
            continue;
        }
        pos.push(rest[i].clone());
        i += 1;
    }

    let mut trad: HashMap<char, String> = HashMap::new();
    for (c, val) in pending.into_iter().zip(pos) {
        trad.insert(c, val);
    }
    let file_t = dashed
        .get("f")
        .filter(|s| !s.is_empty())
        .or_else(|| dashed.get("file").filter(|s| !s.is_empty()))
        .or_else(|| trad.get(&'f').filter(|s| !s.is_empty()))
        .cloned();
    let dest = dashed
        .get("C")
        .filter(|s| !s.is_empty())
        .or_else(|| dashed.get("directory").filter(|s| !s.is_empty()))
        .or_else(|| trad.get(&'C').filter(|s| !s.is_empty()))
        .cloned();
    (letters, longs, file_t, dest)
}

fn guard_targets(words: &[String], depth: usize, cfg: &HookConfig) -> Vec<(String, bool)> {
    let (_assigns, ws) = shlex_util::command_words_with_assigns(words);
    if ws.is_empty() {
        return Vec::new();
    }
    let (mut head, mut rest) = shlex_util::peel_busybox(cmd_base(&ws[0]), &ws[1..]);
    let mut out: Vec<(String, bool)> = Vec::new();
    if matches!(head.as_str(), "bsdtar" | "gtar") {
        head = "tar".to_string();
    }

    if head == "tar" {
        let (letters, longs, fval, _dest) = tar_info(&rest);
        let creates = letters.chars().any(|c| matches!(c, 'c' | 'r' | 'u'))
            || longs
                .iter()
                .any(|x| matches!(x.as_str(), "create" | "append" | "update"));
        if creates {
            if let Some(f) = fval {
                if !f.is_empty() && f != "-" {
                    out.push((f, true));
                }
            }
        }
    } else if head == "patch" {
        for (i, w) in rest.iter().enumerate() {
            if matches!(w.as_str(), "-o" | "--output") && i + 1 < rest.len() {
                out.push((rest[i + 1].clone(), false));
            } else if let Some(val) = w.strip_prefix("--output=") {
                out.push((val.to_string(), false));
            }
        }
    }

    if head == "find" {
        let (roots, expr) = find_split(&rest);
        let root_list: Vec<&str> = if roots.is_empty() { vec!["."] } else { roots };
        for (k, word) in expr.iter().enumerate() {
            if !matches!(
                word.as_str(),
                "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir"
            ) {
                continue;
            }
            for root in &root_list {
                let spots = find_spots(root, cfg);
                let mut hits: Vec<String> = spots
                    .iter()
                    .filter(|(shown, name)| find_may_match(&expr[..k], shown, name))
                    .map(|(shown, _)| shown.clone())
                    .collect();
                if spots.is_empty() && guarded(root, true, None, cfg) {
                    hits = vec![(*root).to_string()];
                }
                if word == "-delete" {
                    for shown in hits {
                        out.push((shown, true));
                    }
                    continue;
                }
                let end = ((k + 1)..expr.len())
                    .find(|&j| matches!(expr[j].as_str(), ";" | "+"))
                    .unwrap_or(expr.len());
                if depth < 3 {
                    for shown in hits {
                        let cmd: Vec<String> = expr[k + 1..end]
                            .iter()
                            .map(|w| w.replace("{}", &shown))
                            .collect();
                        out.extend(guard_targets(&cmd, depth + 1, cfg));
                    }
                }
            }
        }
    }

    if head == "git" {
        let sub = git_sub(&rest);
        if let Some(first) = sub.first().map(String::as_str) {
            if matches!(first, "rm" | "mv") {
                head = first.to_string();
                rest = sub[1..].to_vec();
            } else if first == "clean" && git_clean_takes_ignored(&sub[1..]) {
                let specs = git_clean_pathspecs(&sub[1..]);
                if !specs.is_empty()
                    && !specs
                        .iter()
                        .any(|sp| sp.contains(['*', '?', '[']) || sp.starts_with(':'))
                {
                    return specs.into_iter().map(|sp| (sp, true)).collect();
                }
                return GUARD_SAMPLES
                    .iter()
                    .map(|&g| (g.to_string(), true))
                    .collect();
            } else if first == "stash"
                && cfg.unit_worktree.is_some()
                && git_stash_takes_untracked(&sub[1..])
            {
                return GUARD_SAMPLES
                    .iter()
                    .map(|&g| (g.to_string(), true))
                    .collect();
            }
        }
    }

    let re = regexes();
    match head.as_str() {
        "rm" | "rmdir" | "unlink" | "shred" => {
            for w in operands(&rest, &["-n", "--iterations", "-s", "--size"]) {
                out.push((w, true));
            }
        }
        "mv" | "cp" | "ln" | "install" => {
            let mut tdir: Option<String> = None;
            for (i, w) in rest.iter().enumerate() {
                let ws_item = w.as_str();
                if matches!(ws_item, "-t" | "--target-directory") && i + 1 < rest.len() {
                    tdir = Some(rest[i + 1].clone());
                } else if let Some(val) = ws_item.strip_prefix("--target-directory=") {
                    tdir = Some(val.to_string());
                } else if re.short_end_t.is_match(ws_item) && i + 1 < rest.len() {
                    tdir = Some(rest[i + 1].clone());
                } else if re.short_glued_t.is_match(ws_item) {
                    if let Some(pos) = ws_item.find('t') {
                        tdir = Some(ws_item[pos + 1..].to_string());
                    }
                }
            }
            let ops = operands(
                &rest,
                &[
                    "-t",
                    "--target-directory",
                    "-S",
                    "--suffix",
                    "-m",
                    "--mode",
                    "-o",
                    "--owner",
                    "-g",
                    "--group",
                ],
            );
            let (dests, srcs): (Vec<String>, Vec<String>) = if let Some(td) = tdir {
                (vec![td], ops)
            } else if let Some((last, init)) = ops.split_last() {
                (vec![last.clone()], init.to_vec())
            } else {
                (Vec::new(), Vec::new())
            };
            let whole = rest
                .iter()
                .any(|w| w == "--no-target-directory" || re.short_big_t.is_match(w))
                || srcs.iter().any(|s| s.ends_with("/."));
            for d in &dests {
                out.push((d.clone(), whole));
            }
            for d in &dests {
                for s in &srcs {
                    let combined = format!(
                        "{}/{}",
                        d.trim_end_matches('/'),
                        posix_basename(s.trim_end_matches('/'))
                    );
                    out.push((combined, false));
                }
            }
            if head == "mv" {
                for s in srcs {
                    out.push((s, true));
                }
            }
        }
        "sed" | "perl" => {
            let in_place = rest.iter().any(|w| {
                w == "--in-place" || w.starts_with("--in-place=") || re.short_in_place.is_match(w)
            });
            if in_place {
                let skip_opts: &[&str] = if head == "sed" {
                    &["-e", "-f", "--expression", "--file", "-l"]
                } else {
                    &["-e", "-E", "-M", "-I"]
                };
                for w in operands(&rest, skip_opts) {
                    out.push((w, false));
                }
            }
        }
        "truncate" => {
            for w in operands(&rest, &["-s", "--size", "-r", "--reference"]) {
                out.push((w, false));
            }
        }
        "tee" => {
            for w in operands(&rest, &[]) {
                out.push((w, false));
            }
        }
        "dd" => {
            for w in &rest {
                if let Some(val) = w.strip_prefix("of=") {
                    out.push((val.to_string(), false));
                }
            }
        }
        "chmod" | "chown" | "chgrp" => {
            for w in attr_targets(&head, &rest) {
                out.push((w, true));
            }
        }
        "sort" => {
            for w in sort_outputs(&rest) {
                out.push((w, false));
            }
        }
        "ed" | "red" | "ex" | "vi" | "vim" | "nvim" => {
            for w in editor_targets(&head, &rest) {
                out.push((w, false));
            }
        }
        "rsync" => {
            let ops = operands(&rest, RSYNC_ARG);
            if ops.len() > 1 {
                let (dest, srcs) = ops.split_last().expect("len > 1");
                let whole = rest.iter().any(|w| w.starts_with("--del"))
                    || srcs.iter().any(|s| s.ends_with('/') || s.ends_with("/."));
                out.push((dest.clone(), whole));
                for s in srcs {
                    let combined = format!(
                        "{}/{}",
                        dest.trim_end_matches('/'),
                        posix_basename(s.trim_end_matches('/'))
                    );
                    out.push((combined, false));
                }
                if rest.iter().any(|w| w == "--remove-source-files") {
                    for s in srcs {
                        out.push((s.clone(), true));
                    }
                }
            }
        }
        "curl" | "wget" => {
            for w in fetch_outputs(&head, &rest) {
                out.push((w, false));
            }
        }
        _ => {
            if depth < 3 {
                if let Some(inner) = inner_body_for_guard(&ws) {
                    if !inner.is_empty() {
                        for (_j, seg2) in shlex_util::split_segments(&inner) {
                            let (a2, w2) = shlex_util::tokenize_seg(&seg2);
                            for w in w2 {
                                out.push((w, false));
                            }
                            out.extend(guard_targets(&a2, depth + 1, cfg));
                        }
                    }
                }
            }
        }
    }

    for code in inline_code(&head, &rest) {
        out.extend(code_guard_targets(&code, depth, cfg));
    }
    out
}

fn code_guard_targets(code: &str, depth: usize, cfg: &HookConfig) -> Vec<(String, bool)> {
    let re = regexes();
    let mut out = Vec::new();
    if !re.code_writes.is_match(code) {
        return out;
    }
    for cap in re.code_literal.captures_iter(code) {
        let lit = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        out.push((lit.to_string(), false));
        if depth < 3 && lit.trim().contains(' ') {
            let segs = shlex_util::split_segments(lit);
            let mut any_parsed = false;
            for (_j, seg2) in segs {
                let (a2, _w2) = shlex_util::tokenize_seg(&seg2);
                if !a2.is_empty() {
                    any_parsed = true;
                    out.extend(guard_targets(&a2, depth + 1, cfg));
                }
            }
            if !any_parsed {
                for w in lit.split_whitespace() {
                    out.push((w.to_string(), false));
                }
            }
        }
    }
    out
}

fn coarse_write_targets(text: &str) -> Vec<String> {
    let re = regexes();
    let mut out = Vec::new();
    for cap in re.coarse_write.captures_iter(text) {
        let word = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if word.is_empty() || word == "-" || word.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let unq = word.trim_matches(|c| c == '\'' || c == '"');
        out.push(unq.to_string());
    }
    out
}

// -----------------------------------------------------------------------------
// Root-wipe (Y) & rm option flags
// -----------------------------------------------------------------------------

fn strip_home_prefix(tok: &str) -> Option<&str> {
    if let Some(rest) = tok.strip_prefix("${HOME}") {
        return Some(rest);
    }
    if let Some(rest) = tok.strip_prefix("$HOME") {
        let next_is_ident = rest
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if !next_is_ident {
            return Some(rest);
        }
    }
    None
}

fn rooty(tok: &str) -> Option<&'static str> {
    if tok.is_empty() {
        return None;
    }
    let (base, body) = if tok == "~" || tok.starts_with("~/") {
        ("home", &tok[1..])
    } else if let Some(rest) = strip_home_prefix(tok) {
        ("home", rest)
    } else if tok.starts_with('/') {
        ("root", tok)
    } else {
        return None;
    };
    let mut segs: Vec<&str> = Vec::new();
    for s in body.split('/') {
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            if !segs.is_empty() {
                segs.pop();
            } else if base == "home" {
                return None;
            }
            continue;
        }
        segs.push(if s.contains(['*', '?', '[']) { "*" } else { s });
    }
    if segs.is_empty() || segs == ["*"] {
        Some(base)
    } else {
        None
    }
}

fn rm_opt_flags(rest: &[String]) -> (bool, bool, bool) {
    let mut rec = false;
    let mut frc = false;
    let mut npr = false;
    for w in rest {
        let ws = w.as_str();
        if ws == "--" {
            break;
        }
        if !ws.starts_with('-') || ws == "-" {
            continue;
        }
        if ws.starts_with("--") {
            if ws.len() >= 3 && "--recursive".starts_with(ws) {
                rec = true;
            } else if ws.len() >= 3 && "--force".starts_with(ws) {
                frc = true;
            } else if ws.len() >= 3 && "--no-preserve-root".starts_with(ws) {
                npr = true;
            }
        } else if ws.len() > 1 && ws[1..].bytes().all(|b| b.is_ascii_alphabetic()) {
            if ws[1..].bytes().any(|b| b == b'r' || b == b'R') {
                rec = true;
            }
            if ws[1..].bytes().any(|b| b == b'f') {
                frc = true;
            }
        }
    }
    (rec, frc, npr)
}

fn root_wipe(ws: &[String]) -> bool {
    if ws.is_empty() {
        return false;
    }
    let (head, rest) = shlex_util::peel_busybox(cmd_base(&ws[0]), &ws[1..]);
    if head != "rm" {
        return false;
    }
    let (recursive, _force, _npr) = rm_opt_flags(&rest);
    let targets = operands(&rest, &[]);
    recursive && !targets.is_empty() && targets.iter().any(|t| rooty(t).is_some())
}

// -----------------------------------------------------------------------------
// Parsed Never-list (N)
// -----------------------------------------------------------------------------

fn never_rm(ws: &[String]) -> Option<String> {
    if ws.is_empty() {
        return None;
    }
    let (head, rest) = shlex_util::peel_busybox(cmd_base(&ws[0]), &ws[1..]);
    if head != "rm" {
        return None;
    }
    let (recursive, _force, _npr) = rm_opt_flags(&rest);
    if recursive {
        Some("Recursive delete.".to_string())
    } else {
        None
    }
}

fn never_git(ws: &[String]) -> Option<String> {
    if ws.is_empty() || cmd_base(&ws[0]) != "git" {
        return None;
    }
    let sub = git_sub(&ws[1..]);
    if sub.is_empty() {
        return None;
    }
    let verb = sub[0].as_str();
    let rest = &sub[1..];
    let mut letters = String::new();
    let mut longs: Vec<&str> = Vec::new();
    for w in rest {
        let ws_item = w.as_str();
        if ws_item == "--" {
            break;
        }
        if ws_item.starts_with("--") {
            longs.push(ws_item);
        } else if ws_item.starts_with('-') && ws_item.len() > 1 {
            letters.push_str(&ws_item[1..]);
        }
    }
    let has_long = |names: &[&str]| longs.iter().any(|w| long_is(w, names));
    let force = letters.contains('f') || has_long(&["force"]);
    let whole = rest.iter().any(|w| WHOLE_TREE.contains(&w.as_str()));

    if verb == "branch" && (force || letters.chars().any(|c| matches!(c, 'D' | 'M' | 'C'))) {
        return Some("Force-deleting, force-renaming or resetting a local branch.".to_string());
    }
    if verb == "update-ref" && (letters.contains('d') || has_long(&["delete"])) {
        return Some("Deleting a ref outright.".to_string());
    }
    if verb == "reflog" && matches!(rest.first().map(String::as_str), Some("expire" | "delete")) {
        return Some(
            "Expiring reflog entries, the record that makes discarded commits recoverable."
                .to_string(),
        );
    }
    if verb == "stash" && matches!(rest.first().map(String::as_str), Some("drop" | "clear")) {
        return Some("Dropping stashed work.".to_string());
    }
    if matches!(verb, "filter-repo" | "filter-branch") {
        return Some("Rewriting repository history.".to_string());
    }
    if verb == "worktree" && rest.first().map(String::as_str) == Some("remove") && force {
        return Some("Force-removing a worktree and its uncommitted work.".to_string());
    }
    if verb == "reset" && has_long(&["hard"]) {
        return Some("Discarding uncommitted work.".to_string());
    }
    if matches!(verb, "checkout" | "switch") && (force || has_long(&["discard-changes"])) {
        return Some("Discarding every local change.".to_string());
    }
    if verb == "checkout" && whole {
        return Some("Discarding every local change.".to_string());
    }
    if verb == "restore"
        && whole
        && (letters.contains('W')
            || has_long(&["worktree"])
            || !(letters.contains('S') || has_long(&["staged"])))
    {
        return Some("Discarding every local change.".to_string());
    }
    if verb == "clean" && force && !(letters.contains('n') || has_long(&["dry-run"])) {
        let specs = git_clean_pathspecs(rest);
        if specs.is_empty()
            || specs.iter().any(|sp| {
                WHOLE_TREE.contains(&sp.as_str())
                    || sp.starts_with(':')
                    || sp.contains(['*', '?', '['])
            })
        {
            return Some("Deleting every untracked file in the tree.".to_string());
        }
    }
    None
}

fn never_gh(ws: &[String]) -> Option<String> {
    if ws.is_empty() || cmd_base(&ws[0]) != "gh" {
        return None;
    }
    let rest = &ws[1..];
    let mut i = 0usize;
    while i < rest.len() && rest[i].starts_with('-') {
        i += if GH_OPERAND_FLAGS.contains(&rest[i].as_str()) {
            2
        } else {
            1
        };
    }
    if i >= rest.len() {
        return None;
    }
    let group = rest[i].as_str();
    let tail = &rest[i + 1..];
    let mut verb: Option<&str> = None;
    let mut j = 0usize;
    while j < tail.len() {
        let w = tail[j].as_str();
        if GH_OPERAND_FLAGS.contains(&w) {
            j += 2;
            continue;
        }
        if w.starts_with('-') {
            j += 1;
            continue;
        }
        verb = Some(w);
        break;
    }
    if group == "secret" && matches!(verb, Some("set" | "delete")) {
        return Some("Writing or removing a repository secret.".to_string());
    }
    if group == "repo" && verb == Some("delete") {
        return Some("Deleting a repository.".to_string());
    }
    None
}

fn within(path: &str, top: &str) -> bool {
    path == top || path.starts_with(&format!("{}/", top.trim_end_matches('/')))
}

fn trim_slash_or_root(p: &str) -> String {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        "/".to_string()
    } else {
        t.to_string()
    }
}

fn guard_dirs_resolved(cfg: &HookConfig) -> BTreeSet<String> {
    let groot = cfg.groot.to_string_lossy();
    let mut out = BTreeSet::new();
    for rel in GUARD_DIRS_REL {
        let lexical = posix_join(&groot, rel);
        let real = posix_realpath(&lexical, &cfg.cwd);
        out.insert(trim_slash_or_root(&lexical));
        out.insert(trim_slash_or_root(&real));
    }
    for x in GUARD_SAMPLES {
        let full = posix_join(&groot, x);
        let real = posix_realpath(&full, &cfg.cwd);
        out.insert(trim_slash_or_root(posix_dirname(&real)));
    }
    for me in &cfg.gself {
        let real = posix_realpath(&me.to_string_lossy(), &cfg.cwd);
        out.insert(trim_slash_or_root(posix_dirname(&real)));
    }
    out
}

fn dest_covers_guard(dest: Option<&str>, cfg: &HookConfig) -> bool {
    let Some(dest_raw) = dest else {
        return true;
    };
    let d = shlex_util::home_path(dest_raw, &cfg.home);
    if d == "." || d == "./" || d.split('/').any(|s| s == "..") {
        return true;
    }
    let groot = cfg.groot.to_string_lossy();
    let base = if d.starts_with('/') {
        d
    } else {
        posix_join(&groot, &d)
    };
    let real = trim_slash_or_root(&posix_realpath(&base, &cfg.cwd));
    let root = trim_slash_or_root(&groot);
    if within(&root, &real) {
        return true;
    }
    for gd in guard_dirs_resolved(cfg) {
        if within(&real, &gd) || within(&gd, &real) {
            return true;
        }
    }
    false
}

fn dest_of(rest: &[String], shorts: &str, longnames: &[&str]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        let ws = w.as_str();
        if longnames.contains(&ws) && i + 1 < rest.len() {
            return Some(rest[i + 1].clone());
        }
        for ln in longnames {
            if let Some(after) = ws.strip_prefix(ln) {
                if let Some(val) = after.strip_prefix('=') {
                    return Some(val.to_string());
                }
            }
        }
        if !shorts.is_empty() && ws.starts_with('-') && ws.len() >= 2 {
            let b1 = ws.as_bytes()[1];
            if shorts.as_bytes().contains(&b1) {
                if ws.len() == 2 && i + 1 < rest.len() {
                    return Some(rest[i + 1].clone());
                }
                if ws.len() > 2 && !ws[2..].contains('\n') {
                    return Some(ws[2..].to_string());
                }
            }
        }
    }
    None
}

fn extracts_over_guard(ws: &[String], cfg: &HookConfig) -> Option<String> {
    if ws.is_empty() {
        return None;
    }
    let re = regexes();
    let (head, rest) = shlex_util::peel_busybox(cmd_base(&ws[0]), &ws[1..]);
    let mut letters = String::new();
    let mut longs: Vec<&str> = Vec::new();
    for w in &rest {
        let s = w.as_str();
        if re.short_alpha_flag.is_match(s) {
            letters.push_str(&s[1..]);
        }
        if s.starts_with("--") {
            longs.push(s.split('=').next().unwrap_or(s));
        }
    }

    let dest = match head.as_str() {
        "tar" | "bsdtar" | "gtar" => {
            let (tletters, tlongs, _f, tdest) = tar_info(&rest);
            if !(tletters.contains('x')
                || tlongs
                    .iter()
                    .any(|x| matches!(x.as_str(), "extract" | "get")))
            {
                return None;
            }
            tdest
        }
        "unzip" => dest_of(&rest, "d", &[]),
        "cpio" | "pax"
            if letters.contains('i')
                || letters.contains('r')
                || longs.contains(&"--extract")
                || longs.contains(&"--read") =>
        {
            if head == "pax" && (letters.contains('w') || longs.contains(&"--write")) {
                return None;
            }
            dest_of(&rest, "Cd", DIR_LONGS)
        }
        "patch" => {
            if rest
                .iter()
                .any(|w| w == "-o" || w == "--output" || w.starts_with("--output="))
            {
                return None;
            }
            dest_of(&rest, "d", DIR_LONGS)
        }
        _ => return None,
    };

    if dest_covers_guard(dest.as_deref(), cfg) {
        return Some(
            "Extracting an archive or applying a patch into a directory that holds the hook guard. Its member names are not visible to this hook, so it cannot prove the guard files are untouched; extract into a subdirectory or name the targets."
                .to_string(),
        );
    }
    None
}

fn code_words(ws: &[String]) -> Option<Vec<String>> {
    let head = ws.first().map(|w| cmd_base(w)).unwrap_or("");
    if !(RUNNERS.contains(&head)
        || matches!(canon_interp(head), "python" | "perl" | "ruby" | "php"))
    {
        return None;
    }
    if matches!(head, "eval" | "source" | ".") {
        return Some(ws[1..].to_vec());
    }
    if let Some(body) = inner_body_for_guard(ws) {
        return Some(vec![body]);
    }
    let codes = inline_code(head, &ws[1..]);
    if !codes.is_empty() {
        return Some(codes);
    }
    let first_op = ws[1..]
        .iter()
        .find(|w| !w.starts_with('-'))
        .cloned()
        .into_iter()
        .collect();
    Some(first_op)
}

fn fetch_runs(parsed: &ParsedPayload) -> bool {
    let mut fetch_sub = false;
    for sub in &parsed.subs {
        let segs = shlex_util::split_segments(sub);
        let mut any_seg = false;
        for (_j, seg) in segs {
            let (args, _w) = shlex_util::tokenize_seg(&seg);
            if !args.is_empty() {
                any_seg = true;
                let (_assigns, words) = shlex_util::command_words_with_assigns(&args);
                if words
                    .first()
                    .is_some_and(|w| matches!(cmd_base(w), "curl" | "wget"))
                {
                    fetch_sub = true;
                }
            }
        }
        if !any_seg {
            if let Some(first) = sub.split_whitespace().next() {
                if matches!(cmd_base(first), "curl" | "wget") {
                    fetch_sub = true;
                }
            }
        }
    }
    if fetch_sub && parsed.fed_sub {
        return true;
    }
    let re = regexes();
    let mut fetched: BTreeSet<String> = BTreeSet::new();
    for v in &parsed.all_views {
        if v.words.is_empty() {
            continue;
        }
        let head = cmd_base(&v.words[0]);
        if matches!(head, "curl" | "wget") {
            for p in fetch_outputs(head, &v.words[1..]) {
                fetched.insert(posix_basename(&p).to_string());
            }
            for p in &v.writes {
                fetched.insert(posix_basename(p).to_string());
            }
            continue;
        }
        let code = code_words(&v.words);
        if fetch_sub
            && code.is_some()
            && (code
                .as_ref()
                .is_some_and(|c| c.iter().any(|w| w.contains(SUB_MARK)))
                || re.sub_redir.is_match(&v.seg_text))
        {
            return true;
        }
        if !fetched.is_empty()
            && (code
                .as_ref()
                .is_some_and(|c| c.iter().any(|w| fetched.contains(posix_basename(w))))
                || (v.words[0].contains('/') && fetched.contains(head)))
        {
            return true;
        }
    }
    false
}

// -----------------------------------------------------------------------------
// Inline code & inner body helpers for guard_targets / _fetch_runs
// -----------------------------------------------------------------------------

fn canon_interp(head: &str) -> &str {
    for (prefix, key) in [
        ("python", "python"),
        ("luajit", "luajit"),
        ("lua", "lua"),
        ("ruby", "ruby"),
        ("php", "php"),
        ("perl", "perl"),
    ] {
        if let Some(rest) = head.strip_prefix(prefix) {
            if rest.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                return key;
            }
        }
    }
    head
}

fn inline_flags(key: &str) -> Option<&'static str> {
    match key {
        "python" => Some("c"),
        "perl" | "julia" => Some("eE"),
        "ruby" | "bun" | "lua" | "luajit" | "Rscript" | "R" => Some("e"),
        "node" | "nodejs" => Some("ep"),
        "php" => Some("r"),
        _ => None,
    }
}

fn inline_code(head: &str, rest: &[String]) -> Vec<String> {
    let (head, rest) = shlex_util::peel_busybox(head, rest);
    if is_awk(&head) {
        return awk_sources(&rest).0;
    }
    if head == "deno" {
        let ops: Vec<&String> = rest.iter().filter(|w| !w.starts_with('-')).collect();
        if ops.first().map(|s| s.as_str()) == Some("eval") && ops.len() > 1 {
            return vec![ops[1].clone()];
        }
        return Vec::new();
    }
    let key = canon_interp(&head);
    let Some(letters) = inline_flags(key) else {
        return Vec::new();
    };
    let mut codes = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let w = rest[i].as_str();
        if matches!(w, "--eval" | "--print") && i + 1 < rest.len() {
            codes.push(rest[i + 1].clone());
            i += 1;
        } else if !w.starts_with("--") && w.starts_with('-') && w.len() > 1 {
            if let Some((after_flag, matched)) = match_short_inline_flag(&w[1..], letters) {
                if matched {
                    let tail = &w[1 + after_flag..];
                    if !tail.is_empty() {
                        codes.push(tail.to_string());
                    } else if i + 1 < rest.len() {
                        codes.push(rest[i + 1].clone());
                        i += 1;
                    }
                    if key == "python" {
                        break;
                    }
                }
            }
        } else if key == "python"
            && matches!(w, "-W" | "-X" | "--check-hash-based-pycs")
            && i + 1 < rest.len()
        {
            i += 1;
        } else if key == "python" && !w.starts_with('-') {
            break;
        }
        i += 1;
    }
    codes
}

fn match_short_inline_flag(cluster: &str, letters: &str) -> Option<(usize, bool)> {
    for (byte_idx, ch) in cluster.char_indices() {
        if letters.contains(ch) {
            return Some((byte_idx + ch.len_utf8(), true));
        }
        if !ch.is_ascii_alphabetic() {
            return None;
        }
    }
    None
}

fn peel_shell(ws: &[String]) -> Vec<String> {
    if let Some(first) = ws.first() {
        let (head, rest) = shlex_util::peel_busybox(cmd_base(first), &ws[1..]);
        if SHELLS.contains(&head.as_str()) && rest.len() < ws.len() - 1 {
            let mut out = Vec::with_capacity(1 + rest.len());
            out.push(head);
            out.extend(rest);
            return out;
        }
    }
    ws.to_vec()
}

fn opt_end(rest: &[String], takes: &str, longs: &[&str]) -> usize {
    let mut i = 0usize;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            return i + 1;
        }
        if w.starts_with("--") {
            i += if !w.contains('=') && longs.contains(&w) {
                2
            } else {
                1
            };
        } else if w.starts_with('-') && w.len() > 1 {
            let tail = &w[1..];
            let takes_next = tail
                .char_indices()
                .find(|&(_, f)| takes.contains(f))
                .is_some_and(|(idx, f)| idx + f.len_utf8() == tail.len());
            i += if takes_next { 2 } else { 1 };
        } else {
            return i;
        }
    }
    i
}

fn dash_c(rest: &[String], names: &[&str]) -> Option<String> {
    let re = regexes();
    for (i, w) in rest.iter().enumerate() {
        let ws = w.as_str();
        if (names.contains(&ws) || re.short_c_cluster.is_match(ws)) && i + 1 < rest.len() {
            return Some(rest[i + 1].clone());
        }
        for name in names {
            if name.starts_with("--") {
                if let Some(after) = ws.strip_prefix(name) {
                    if let Some(val) = after.strip_prefix('=') {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

fn launcher_bodies(head: &str, rest: &[String]) -> Vec<String> {
    let re = regexes();
    match head {
        "su" | "runuser" => {
            if let Some(body) = dash_c(rest, &["-c", "--command", "--session-command"]) {
                return vec![body];
            }
            let i = opt_end(
                rest,
                "ugGsw",
                &[
                    "--user",
                    "--group",
                    "--supp-group",
                    "--shell",
                    "--whitelist-environment",
                ],
            );
            let named = rest[..i.min(rest.len())]
                .iter()
                .any(|w| matches!(w.as_str(), "-u" | "--user") || w.starts_with("--user="));
            if head == "runuser" && named && i < rest.len() {
                vec![shlex_join(&rest[i..])]
            } else {
                Vec::new()
            }
        }
        "flock" => {
            if let Some(body) = dash_c(rest, &["-c", "--command"]) {
                return vec![body];
            }
            let i = opt_end(rest, "wE", &["--wait", "--timeout", "--conflict-exit-code"]) + 1;
            if i < rest.len() {
                vec![shlex_join(&rest[i..])]
            } else {
                Vec::new()
            }
        }
        "script" => {
            if let Some(body) = dash_c(rest, &["-c", "--command"]) {
                return vec![body];
            }
            let i = opt_end(
                rest,
                "tTIOBEm",
                &[
                    "--log-timing",
                    "--log-in",
                    "--log-out",
                    "--log-io",
                    "--echo",
                    "--output-limit",
                    "--logging-format",
                ],
            );
            let ops = rest.get(i..).unwrap_or(&[]);
            if ops.len() > 1 {
                vec![shlex_join(&ops[1..])]
            } else {
                Vec::new()
            }
        }
        "watch" => {
            let i = opt_end(rest, "nq", &["--interval", "--equexit"]);
            let vector = rest[..i.min(rest.len())]
                .iter()
                .any(|w| w == "--exec" || re.short_x_cluster.is_match(w));
            let tail = rest.get(i..).unwrap_or(&[]);
            if tail.is_empty() {
                Vec::new()
            } else if vector {
                vec![shlex_join(tail)]
            } else {
                vec![tail.join(" ")]
            }
        }
        "parallel" => {
            let start = opt_end(rest, "jPSadEInNLlsC", PARALLEL_LONG);
            let slice = rest.get(start..).unwrap_or(&[]);
            let mut tpl: &[String] = slice;
            let mut args: Vec<String> = Vec::new();
            for (k, w) in slice.iter().enumerate() {
                if PARALLEL_SEPS.contains(&w.as_str()) {
                    tpl = &slice[..k];
                    args = slice[k + 1..]
                        .iter()
                        .filter(|a| !PARALLEL_SEPS.contains(&a.as_str()))
                        .cloned()
                        .collect();
                    break;
                }
            }
            if tpl.is_empty() {
                return args;
            }
            let has_ph = tpl.iter().any(|w| re.parallel_ph.is_match(w));
            let iter_args = if args.is_empty() {
                vec![String::new()]
            } else {
                args
            };
            let mut out = Vec::new();
            for a in iter_args {
                let mut filled: Vec<String> = tpl
                    .iter()
                    .map(|w| re.parallel_ph.replace_all(w, a.as_str()).into_owned())
                    .collect();
                if !has_ph && !a.is_empty() {
                    filled.push(a);
                }
                out.push(filled.join(" "));
            }
            out
        }
        "ssh" => {
            let takes = "BbcDEeFIiJLlmOoPpQRSWw";
            let i = opt_end(rest, takes, &[]);
            if i >= rest.len() {
                return Vec::new();
            }
            let j = i + 1 + opt_end(&rest[i + 1..], takes, &[]);
            let tail = rest.get(j..).unwrap_or(&[]);
            if tail.is_empty() {
                Vec::new()
            } else {
                vec![tail.join(" ")]
            }
        }
        "fd" | "fdfind" => {
            let mut out = Vec::new();
            let mut i = 0usize;
            while i < rest.len() {
                let w = rest[i].as_str();
                let is_exec = w.starts_with("--exec=")
                    || w.starts_with("--exec-batch=")
                    || matches!(w, "--exec" | "--exec-batch")
                    || re.fd_short_exec.is_match(w);
                if is_exec {
                    let mut j = i + 1;
                    while j < rest.len() && rest[j] != ";" {
                        j += 1;
                    }
                    let mut vec_cmd = Vec::new();
                    if let Some((_, val)) = w.split_once('=') {
                        vec_cmd.push(val.to_string());
                    }
                    vec_cmd.extend(rest[i + 1..j].iter().cloned());
                    if !vec_cmd.is_empty() {
                        out.push(shlex_join(&vec_cmd));
                    }
                    i = j;
                }
                i += 1;
            }
            out
        }
        "entr" => {
            let mut i = 0usize;
            while i < rest.len() && re.entr_flags.is_match(&rest[i]) {
                i += 1;
            }
            if rest.get(i).map(String::as_str) == Some("--") {
                i += 1;
            }
            let shell = rest[..i.min(rest.len())]
                .iter()
                .any(|w| w != "--" && w.contains('s'));
            let tail = rest.get(i..).unwrap_or(&[]);
            if tail.is_empty() {
                Vec::new()
            } else if shell {
                vec![tail[0].clone()]
            } else {
                vec![shlex_join(tail)]
            }
        }
        "repeat" => {
            if rest.len() > 1 {
                vec![shlex_join(&rest[1..])]
            } else {
                Vec::new()
            }
        }
        "find" => {
            let mut out = Vec::new();
            let mut i = 0usize;
            while i < rest.len() {
                if matches!(rest[i].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                    let mut j = i + 1;
                    while j < rest.len() && !matches!(rest[j].as_str(), ";" | "+") {
                        j += 1;
                    }
                    if j > i + 1 {
                        out.push(shlex_join(&rest[i + 1..j]));
                    }
                    i = j;
                }
                i += 1;
            }
            out
        }
        _ => Vec::new(),
    }
}

fn sed_s_execs(script: &str) -> Vec<String> {
    let chars: Vec<char> = script.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if chars[i] == 's'
            && i + 1 < n
            && !(chars[i + 1].is_alphanumeric() || matches!(chars[i + 1], ' ' | '\t' | '\n'))
        {
            let delim = chars[i + 1];
            let mut j = i + 2;
            let mut parts: Vec<String> = Vec::new();
            let mut cur = String::new();
            while j < n && parts.len() < 2 {
                let c = chars[j];
                if c == '\\' && j + 1 < n {
                    if chars[j + 1] == delim {
                        cur.push(chars[j + 1]);
                    } else {
                        cur.push(c);
                        cur.push(chars[j + 1]);
                    }
                    j += 2;
                    continue;
                }
                if c == '\n' {
                    break;
                }
                if c == delim {
                    parts.push(std::mem::take(&mut cur));
                    j += 1;
                    continue;
                }
                cur.push(c);
                j += 1;
            }
            let mut flags = String::new();
            while j < n && !matches!(chars[j], ' ' | '\t' | '\n' | ';') {
                flags.push(chars[j]);
                j += 1;
            }
            if parts.len() == 2 && flags.contains('e') {
                out.push(parts.swap_remove(1));
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn shell_launcher_lines(head: &str, rest: &[String]) -> Vec<String> {
    let re = regexes();
    let mut lines = Vec::new();
    if head == "sqlite3" {
        let mut texts = Vec::new();
        let mut i = 0usize;
        while i < rest.len() {
            let w = rest[i].as_str();
            if matches!(w, "-cmd" | "-init") && i + 1 < rest.len() {
                texts.push(rest[i + 1].as_str());
                i += 2;
                continue;
            }
            if !w.starts_with('-') {
                texts.push(w);
            }
            i += 1;
        }
        for text in texts {
            for ln in text.split('\n') {
                if let Some(cap) = re.sqlite_dot.captures(ln) {
                    if let Some(m) = cap.get(2) {
                        lines.push(m.as_str().trim().to_string());
                    }
                }
            }
        }
    } else if head == "sed" {
        let mut scripts = Vec::new();
        let mut i = 0usize;
        while i < rest.len() {
            let w = rest[i].as_str();
            if matches!(w, "-e" | "--expression") && i + 1 < rest.len() {
                scripts.push(rest[i + 1].clone());
                i += 2;
                continue;
            }
            if matches!(w, "-f" | "--file" | "-l" | "--line-length") {
                i += 2;
                continue;
            }
            if let Some(val) = w.strip_prefix("--expression=") {
                scripts.push(val.to_string());
            } else if w.starts_with('-') && !w.starts_with("--") && w.len() > 1 {
                for (byte_idx, flag) in w[1..].char_indices() {
                    if matches!(flag, 'e' | 'f' | 'l') {
                        let after = 1 + byte_idx + flag.len_utf8();
                        let mut operand = w[after..].to_string();
                        if operand.is_empty() && i + 1 < rest.len() {
                            i += 1;
                            operand = rest[i].clone();
                        }
                        if flag == 'e' {
                            scripts.push(operand);
                        }
                        break;
                    }
                }
            } else if !w.starts_with('-') {
                scripts.push(w.to_string());
                break;
            }
            i += 1;
        }
        for script in scripts {
            for piece in script.split([';', '\n']) {
                if let Some(cap) = re.sed_exec_line.captures(piece) {
                    if let Some(m) = cap.get(1) {
                        lines.push(m.as_str().trim().to_string());
                    }
                }
            }
            lines.extend(sed_s_execs(&script));
        }
    }
    lines
}

fn call_args(code: &str, open_paren: usize) -> &str {
    let bytes = code.as_bytes();
    let n = bytes.len();
    let mut depth = 0i32;
    let mut i = open_paren;
    let mut quote: u8 = 0;
    while i < n {
        let b = bytes[i];
        if quote != 0 {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == quote {
                quote = 0;
            }
        } else if b == b'\'' || b == b'"' {
            quote = b;
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return &code[open_paren + 1..i];
            }
        }
        i += 1;
    }
    &code[open_paren + 1..]
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn code_commands(code: &str) -> Vec<String> {
    let re = regexes();
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for m in re.exec_call.find_iter(code) {
        if m.start() > 0 && is_ident_byte(bytes[m.start() - 1]) {
            continue;
        }
        let argtext = call_args(code, m.end() - 1);
        let abytes = argtext.as_bytes();
        let an = abytes.len();
        let mut i = 0usize;
        while i < an {
            let opens_seq = abytes[i] == b'['
                || (abytes[i] == b'('
                    && (i == 0
                        || !(is_ident_byte(abytes[i - 1])
                            || matches!(abytes[i - 1], b'.' | b']' | b')'))));
            if opens_seq {
                let mut j = i + 1;
                while j < an && !matches!(abytes[j], b'[' | b']' | b'(' | b')') {
                    j += 1;
                }
                if j == an || matches!(abytes[j], b']' | b')') {
                    let inner = &argtext[i + 1..j];
                    let items: Vec<String> = re
                        .code_literal
                        .captures_iter(inner)
                        .filter_map(|c| {
                            let s = c.get(1).or_else(|| c.get(2)).map(|x| x.as_str())?;
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            }
                        })
                        .collect();
                    if items.len() > 1 {
                        out.push(shlex_join(&items));
                    }
                    i = if j < an { j + 1 } else { an };
                    continue;
                }
            }
            i += 1;
        }
        for cap in re.code_literal.captures_iter(argtext) {
            let s = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|x| x.as_str())
                .unwrap_or("");
            out.push(s.to_string());
        }
    }
    // Backtick command literals inside interpreter code.
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            if let Some(rel_end) = code[i + 1..].find('`') {
                out.push(code[i + 1..i + 1 + rel_end].to_string());
                i += rel_end + 2;
                continue;
            }
        }
        i += 1;
    }
    out.into_iter().filter(|l| !l.trim().is_empty()).collect()
}

fn awk_pipe_cmds(code: &str) -> Vec<String> {
    let re = regexes();
    let bytes = code.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    for cap in re.code_literal.captures_iter(code) {
        let Some(full) = cap.get(0) else {
            continue;
        };
        let inner = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if inner.trim().is_empty() {
            continue;
        }
        // Check `"cmd" | ...` or `"cmd" |& ...`
        let mut after = full.end();
        while after < n && matches!(bytes[after], b' ' | b'\t') {
            after += 1;
        }
        if after < n && bytes[after] == b'|' && bytes.get(after + 1) != Some(&b'|') {
            out.push(inner.to_string());
        }
        // Check `... | "cmd"` or `... |& "cmd"`
        let mut before = full.start();
        while before > 0 && matches!(bytes[before - 1], b' ' | b'\t') {
            before -= 1;
        }
        let is_pipe_before =
            if before >= 2 && bytes[before - 1] == b'&' && bytes[before - 2] == b'|' {
                before < 3 || bytes[before - 3] != b'|'
            } else if before >= 1 && bytes[before - 1] == b'|' {
                before < 2 || bytes[before - 2] != b'|'
            } else {
                false
            };
        if is_pipe_before {
            out.push(inner.to_string());
        }
    }
    out
}

fn guard_text_fetch_body(ws: &[String]) -> Option<String> {
    if ws.is_empty() {
        return None;
    }
    let head = cmd_base(&ws[0]);
    let idx = if head == "guard_text.py" {
        Some(0usize)
    } else if canon_interp(head) == "python" {
        let mut i = 1usize;
        while i < ws.len() {
            let w = ws[i].as_str();
            if w == "--" {
                i += 1;
                break;
            }
            if matches!(w, "-W" | "-X") {
                i += 2;
            } else if ((w.starts_with("-W") || w.starts_with("-X")) && w.len() > 2)
                || (w.starts_with('-')
                    && !w.starts_with("--")
                    && !w[1..].chars().any(|c| matches!(c, 'c' | 'm')))
            {
                i += 1;
            } else {
                break;
            }
        }
        if i < ws.len() && cmd_base(&ws[i]) == "guard_text.py" {
            Some(i)
        } else {
            None
        }
    } else {
        None
    }?;
    let rest = &ws[idx + 1..];
    for (k, w) in rest.iter().enumerate() {
        if w == "--fetch" && k + 1 < rest.len() {
            return Some(shlex_join(&rest[k + 1..]));
        }
        if let Some(val) = w.strip_prefix("--fetch=") {
            let mut tail = Vec::new();
            if !val.is_empty() {
                tail.push(val.to_string());
            }
            tail.extend(rest[k + 1..].iter().filter(|t| !t.is_empty()).cloned());
            if !tail.is_empty() {
                return Some(shlex_join(&tail));
            }
            return None;
        }
    }
    None
}

fn inner_body_for_guard(ws: &[String]) -> Option<String> {
    if ws.is_empty() {
        return None;
    }
    let ws = peel_shell(ws);
    let head = cmd_base(&ws[0]);
    let re = regexes();
    let mut bodies: Vec<String> = Vec::new();

    if head == "eval" {
        let rest = if ws.get(1).map(String::as_str) == Some("--") {
            &ws[2..]
        } else {
            &ws[1..]
        };
        bodies.push(rest.join(" "));
    } else if SHELLS.contains(&head) {
        let mut has_c = false;
        let mut i = 1usize;
        while i < ws.len() {
            let word = ws[i].as_str();
            if word == "--" {
                i += 1;
                break;
            }
            if matches!(word, "-o" | "+o" | "-O" | "+O") {
                i += 2;
            } else if re.shell_short_flag.is_match(word) {
                if word.starts_with('-') && word.contains('c') {
                    has_c = true;
                }
                i += 1;
            } else if word.starts_with("--") {
                i += 1;
            } else {
                break;
            }
        }
        if has_c && i < ws.len() {
            bodies.push(ws[i].clone());
        }
    } else if head == "trap" {
        let rest = if ws.get(1).map(String::as_str) == Some("--") {
            &ws[2..]
        } else {
            &ws[1..]
        };
        if let Some(first) = rest.first() {
            if !matches!(first.as_str(), "-" | "-l" | "-p" | "-P") {
                bodies.push(first.clone());
            }
        }
    } else if head == "alias" {
        for w in &ws[1..] {
            if !w.starts_with('-') {
                if let Some((_, val)) = w.split_once('=') {
                    bodies.push(val.to_string());
                }
            }
        }
    } else if BODY_LAUNCHERS.contains(&head) {
        bodies.extend(launcher_bodies(head, &ws[1..]));
    } else if head == "gh" {
        if let Some((verb, _name, Some(exp), true)) = shlex_util::gh_alias_detail(&ws) {
            if verb == "set" {
                bodies.push(exp);
            }
        }
    } else if head == "git" {
        bodies.extend(shlex_util::git_bodies(&ws[1..]));
    } else if matches!(head, "sqlite3" | "sed")
        || shlex_util::peel_busybox(head, &ws[1..]).0 == "sed"
    {
        let (ph, pr) = shlex_util::peel_busybox(head, &ws[1..]);
        bodies.extend(shell_launcher_lines(&ph, &pr));
    } else {
        let is_awk_cmd = is_awk(&shlex_util::peel_busybox(head, &ws[1..]).0);
        for code in inline_code(head, &ws[1..]) {
            bodies.extend(code_commands(&code));
            if is_awk_cmd {
                bodies.extend(awk_pipe_cmds(&code));
            }
        }
    }

    if let Some(gt) = guard_text_fetch_body(&ws) {
        bodies.push(gt);
    }
    if bodies.is_empty() {
        return None;
    }
    Some(
        bodies
            .into_iter()
            .map(|b| b.replace(QNL, "\n"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

// -----------------------------------------------------------------------------
// POSIX path & shell quoting utilities
// -----------------------------------------------------------------------------

fn cmd_base(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn posix_basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn posix_dirname(p: &str) -> &str {
    match p.rfind('/') {
        None => "",
        Some(0) => "/",
        Some(i) => {
            let head = &p[..i];
            let trimmed = head.trim_end_matches('/');
            if trimmed.is_empty() {
                head
            } else {
                trimmed
            }
        }
    }
}

fn expand_tilde(p: &str, home: &str) -> String {
    if p.starts_with('~') {
        shlex_util::home_path(p, home)
    } else {
        p.to_string()
    }
}

fn posix_join(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if base.is_empty() || base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let initial_slashes = if path.starts_with('/') {
        if path.starts_with("//") && !path.starts_with("///") {
            2
        } else {
            1
        }
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if (initial_slashes == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
                comps.push("..");
            } else if !comps.is_empty() {
                comps.pop();
            }
        } else {
            comps.push(comp);
        }
    }
    let mut out = String::new();
    for _ in 0..initial_slashes {
        out.push('/');
    }
    out.push_str(&comps.join("/"));
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

fn posix_realpath(path: &str, cwd: &Path) -> String {
    let start = if path.starts_with('/') {
        path.to_string()
    } else {
        posix_join(&cwd.to_string_lossy(), path)
    };
    if let Ok(canon) = fs::canonicalize(&start) {
        return canon.to_string_lossy().into_owned();
    }
    let mut stack: Vec<String> = start
        .split('/')
        .filter(|s| !s.is_empty())
        .rev()
        .map(String::from)
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut hops = 0usize;
    while let Some(comp) = stack.pop() {
        if comp == "." {
            continue;
        }
        if comp == ".." {
            out.pop();
            continue;
        }
        let cur = if out.is_empty() {
            format!("/{comp}")
        } else {
            format!("/{}/{comp}", out.join("/"))
        };
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() && hops < 40 => {
                if let Ok(target) = fs::read_link(&cur) {
                    hops += 1;
                    let tstr = target.to_string_lossy();
                    if tstr.starts_with('/') {
                        out.clear();
                    }
                    for piece in tstr.split('/').filter(|s| !s.is_empty()).rev() {
                        stack.push(piece.to_string());
                    }
                    continue;
                }
                out.push(comp);
            }
            _ => out.push(comp),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
            )
    });
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

fn shlex_join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| shlex_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_cfg(root: &str) -> HookConfig {
        HookConfig {
            unit_worktree: Some(root.to_string()),
            dh_self: Some(PathBuf::from("/opt/fleet/runtime/scripts/deny-hook.sh")),
            current_exe: None,
            hook_strict: false,
            hook_readonly: false,
            headless_strict: false,
            goose_mode: false,
            cwd: PathBuf::from(root),
            groot: PathBuf::from(root),
            gself: BTreeSet::from([PathBuf::from("/opt/fleet/runtime/scripts/deny-hook.sh")]),
            egress_sibling: None,
            state_db: None,
            worker_id: "w1".to_string(),
            run_id: "r1".to_string(),
            home: "/home/tester".to_string(),
            jcode_tool_name: None,
        }
    }

    fn sv(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn awk_program_file_detection() {
        assert!(awk_program_file(&sv(&["awk", "-f", "prog.awk", "in.txt"])).is_some());
        assert!(awk_program_file(&sv(&["gawk", "-E", "prog.awk"])).is_some());
        assert!(awk_program_file(&sv(&["busybox", "awk", "-e", "{print}", "-fp.awk"])).is_some());
        assert!(awk_program_file(&sv(&["awk", "-F:", "{print $1}", "in.txt"])).is_none());
        assert!(awk_program_file(&sv(&["awk", "-v", "f=1", "{print f}"])).is_none());
    }

    #[test]
    fn git_config_laundering_rules() {
        assert!(git_alias_laundering(&[], &sv(&["git", "-c", "alias.p=push", "p"])).is_some());
        assert!(git_alias_laundering(
            &[],
            &sv(&["git", "-c", "remote.origin.mirror=true", "push"])
        )
        .is_some());
        assert!(git_alias_laundering(&[], &sv(&["git", "-c", "core.pager=cat", "log"])).is_none());
        assert!(git_alias_laundering(&[], &sv(&["git", "-c", "core.pager=", "log"])).is_none());
        assert!(git_alias_laundering(&[], &sv(&["git", "-c", "core.pager=sh", "log"])).is_some());
        assert!(
            git_alias_laundering(&sv(&["GIT_CONFIG_KEY_0=alias.x"]), &sv(&["git", "status"]))
                .is_some()
        );
        assert!(git_alias_laundering(
            &sv(&["GIT_CONFIG_PARAMETERS='core.sshCommand=evil'"]),
            &sv(&["git", "fetch"])
        )
        .is_some());
        assert!(git_alias_laundering(&[], &sv(&["git", "config", "alias.p", "push"])).is_some());
        assert!(git_alias_laundering(&[], &sv(&["git", "config", "--get", "alias.p"])).is_none());
    }

    #[test]
    fn self_guard_and_case_folding() {
        let cfg = test_cfg("/tmp/of-hook-test-wt");
        assert!(guarded(".claude/settings.json", false, None, &cfg));
        assert!(guarded(".CLAUDE/SETTINGS.JSON", false, None, &cfg));
        assert!(guarded(".orca/human-grant-pubkey", false, None, &cfg));
        assert!(guarded(".orca/dispatch-pubkey", false, None, &cfg));
        assert!(!guarded(".orca/other.txt", false, None, &cfg));
        assert!(guarded(".orca", true, None, &cfg));
        assert!(guarded(
            "/opt/fleet/runtime/scripts/deny-hook.sh",
            false,
            None,
            &cfg
        ));
        assert!(!guarded("src/main.rs", false, None, &cfg));
        assert!(guarded(
            "settings.json",
            false,
            Some("/tmp/of-hook-test-wt/.claude"),
            &cfg
        ));
    }

    #[test]
    fn guard_targets_commands() {
        let cfg = test_cfg("/tmp/of-hook-test-wt");
        assert!(guard_targets(&sv(&["chmod", "+x", ".claude/settings.json"]), 0, &cfg).is_empty());
        assert!(
            !guard_targets(&sv(&["chmod", "000", ".claude/settings.json"]), 0, &cfg).is_empty()
        );
        assert!(!guard_targets(&sv(&["chmod", "-x", ".claude/settings.json"]), 0, &cfg).is_empty());
        assert!(
            !guard_targets(&sv(&["tar", "cf", ".claude/settings.json", "x"]), 0, &cfg).is_empty()
        );
        assert!(!guard_targets(&sv(&["git", "clean", "-fdx"]), 0, &cfg).is_empty());
        assert_eq!(
            guard_targets(&sv(&["git", "clean", "-fdx", "--", "build/"]), 0, &cfg),
            vec![("build/".to_string(), true)]
        );
    }

    #[test]
    fn rooty_and_root_wipe_cases() {
        assert_eq!(rooty("/"), Some("root"));
        assert_eq!(rooty("/*/"), Some("root"));
        assert_eq!(rooty("/dev/../"), Some("root"));
        assert_eq!(rooty("~"), Some("home"));
        assert_eq!(rooty("~/*"), Some("home"));
        assert_eq!(rooty("~/."), Some("home"));
        assert_eq!(rooty("${HOME}/*"), Some("home"));
        assert_eq!(rooty("$HOME/."), Some("home"));
        assert_eq!(rooty("$HOME_DIR"), None);
        assert_eq!(rooty("~/.."), None);
        assert_eq!(rooty("/tmp/foo"), None);
        assert!(root_wipe(&sv(&["rm", "--rec", "/*/"])));
        assert!(!root_wipe(&sv(&["rm", "-rf", "/tmp/foo"])));
    }

    #[test]
    fn parsed_never_rules() {
        let cfg = test_cfg("/tmp/of-hook-test-wt");
        assert!(never_git(&sv(&["git", "branch", "-D", "feat"])).is_some());
        assert!(never_git(&sv(&["git", "reset", "--hard"])).is_some());
        assert!(never_git(&sv(&["git", "restore", "--staged", "."])).is_none());
        assert!(never_git(&sv(&["git", "restore", "."])).is_some());
        assert!(never_gh(&sv(&["gh", "-R", "o/r", "secret", "set", "K"])).is_some());
        assert!(never_gh(&sv(&["gh", "repo", "delete", "o/r"])).is_some());
        assert!(never_rm(&sv(&["rm", "--rec", "dir"])).is_some());
        assert!(extracts_over_guard(&sv(&["tar", "xf", "a.tar"]), &cfg).is_some());
        assert!(
            extracts_over_guard(&sv(&["tar", "-C", ".claude", "-xf", "a.tar"]), &cfg).is_some()
        );
        assert!(extracts_over_guard(&sv(&["tar", "-C", "sub", "-xf", "a.tar"]), &cfg).is_none());
        assert!(extracts_over_guard(&sv(&["patch", "-o", "out.txt"]), &cfg).is_none());
    }
}
