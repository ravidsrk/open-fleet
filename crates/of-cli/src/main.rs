//! `open-fleet` — native Rust engine binary with strangler-fig delegation for not-yet-ported verbs.

use clap::{Parser, Subcommand};
use of_floor::FloorConfig;
use of_install::{InstallConfig, HARNESS_PROFILES};
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "open-fleet",
    version = ENGINE_VERSION,
    about = "The proof layer and autonomous fleet engine for coding agents.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Diff-scoped floor guard: block suppressed checkers, skipped tests, deleted assertions, lowered thresholds, and guard-surface edits.
    Floor {
        /// Base ref (default: origin/HEAD -> origin/main -> origin/master -> main -> master).
        #[arg(long)]
        base: Option<String>,
        /// Constraints file whose numbered floors may not go down.
        #[arg(long, default_value = "CONSTRAINTS.md")]
        constraints: String,
        /// DECISIONS log path, read AT THE BASE REF.
        #[arg(long, default_value = "docs/DECISIONS.md")]
        waivers: String,
        /// Repository to guard (default: cwd).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Print findings only, suppress the clean banner.
        #[arg(long)]
        quiet: bool,
        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Install open-fleet skills and native hooks into your coding agent harness(es).
    #[command(alias = "install")]
    Init {
        /// Target harness: claude, cursor, codex, gemini, opencode, antigravity, or all.
        #[arg(long, default_value = "claude")]
        harness: String,
        /// Installation scope: user ($HOME) or project (--repo).
        #[arg(long, default_value = "user")]
        scope: String,
        /// Link mode: symlink or copy.
        #[arg(long, default_value = "symlink")]
        mode: String,
        /// Override home directory (defaults to $HOME).
        #[arg(long)]
        home: Option<PathBuf>,
        /// Repository / catalog directory (default: cwd).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Wire native floor-guard hooks into supported harness settings (default true for init).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        with_hooks: bool,
        /// Preview actions without writing files.
        #[arg(long)]
        dry_run: bool,
        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Check engine binary, git, catalog, runtime mode, and installed agent harnesses.
    Doctor {
        /// Repository directory (default: cwd).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Run a guardrail hook (`floor` runs natively; `deny` delegates to deny-hook.sh until Wave 1.5).
    Hook {
        /// Hook mode: `floor` (native diff floor check) or `deny` (pre-tool-use command guard).
        #[arg(long, default_value = "floor")]
        mode: String,
        /// Repository directory (default: cwd).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Remaining arguments forwarded to the hook engine.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<OsString>,
    },
    /// Delegate Waves 2–4 verbs (verify, mcp, ui, missions, run, ci-check, ...) to the catalog Python runtime.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

fn default_home() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn delegate_python(subcmd: &[OsString]) -> i32 {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(root) = of_install::find_catalog_root(&cwd) else {
        eprintln!(
            "open-fleet: subcommand {:?} requires the open-fleet catalog checkout (set OPEN_FLEET_ROOT or run inside the repo)",
            subcmd.first().map(|s| s.to_string_lossy()).unwrap_or_default()
        );
        return 2;
    };
    let name = subcmd
        .first()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let script_map: &[(&str, &str)] = &[
        ("verify", "runtime/scripts/verify.py"),
        ("egress", "runtime/scripts/egress.py"),
        ("decisions", "runtime/scripts/decisions.py"),
        ("events", "runtime/scripts/events.py"),
        ("queue", "runtime/scripts/merge_queue.py"),
        ("upstream-probe", "runtime/scripts/upstream_probe.py"),
    ];

    let python = of_install::which("python3")
        .or_else(|| of_install::which("python"))
        .unwrap_or_else(|| PathBuf::from("python3"));

    let mut cmd = Command::new(python);
    if let Some((_, rel)) = script_map.iter().find(|(k, _)| *k == name) {
        cmd.arg("-I").arg(root.join(rel)).args(&subcmd[1..]);
    } else {
        cmd.arg("-m").arg("open_fleet").args(subcmd);
        let existing = env::var_os("PYTHONPATH").unwrap_or_default();
        let mut py_path = OsString::from(root.as_os_str());
        if !existing.is_empty() {
            py_path.push(if cfg!(windows) { ";" } else { ":" });
            py_path.push(existing);
        }
        cmd.env("PYTHONPATH", py_path);
    }

    match cmd.status() {
        Ok(st) => st.code().unwrap_or(1),
        Err(err) => {
            eprintln!("open-fleet: failed to launch python delegate for {name:?}: {err}");
            2
        }
    }
}

fn delegate_deny_hook(repo: &Path, rest: &[OsString]) -> i32 {
    let Some(root) = of_install::find_catalog_root(repo) else {
        eprintln!(
            "open-fleet: hook --mode deny requires the open-fleet catalog (set OPEN_FLEET_ROOT)"
        );
        return 2;
    };
    let script = root.join("runtime/scripts/deny-hook.sh");
    match Command::new("bash").arg(script).args(rest).status() {
        Ok(st) => st.code().unwrap_or(1),
        Err(err) => {
            eprintln!("open-fleet: failed to execute deny-hook.sh: {err}");
            2
        }
    }
}

fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Commands::Floor {
            base,
            constraints,
            waivers,
            repo,
            quiet,
            json,
        } => of_floor::run(&FloorConfig {
            base,
            constraints,
            waivers,
            repo,
            quiet,
            json,
        }),
        Commands::Init {
            harness,
            scope,
            mode,
            home,
            repo,
            with_hooks,
            dry_run,
            json,
        } => {
            let cfg = InstallConfig {
                harness,
                scope,
                mode,
                home: home.unwrap_or_else(default_home),
                repo,
                with_hooks,
                dry_run,
                json,
            };
            match of_install::install(&cfg) {
                Ok(report) => {
                    if json {
                        if let Ok(s) = serde_json::to_string_pretty(&report) {
                            println!("{s}");
                        }
                    } else {
                        let prefix = if report.dry_run { "[dry-run] " } else { "" };
                        println!(
                            "{prefix}open-fleet init ({}, {}): catalog {}",
                            report.scope, report.mode, report.catalog_root
                        );
                        for t in &report.targets {
                            let hook_note = if t.hook_wired {
                                format!(
                                    " + floor hook wired in {}",
                                    t.settings_path.as_deref().unwrap_or("settings.json")
                                )
                            } else {
                                String::new()
                            };
                            println!(
                                "  - {} ({}): {} mission(s) -> {}{hook_note}",
                                t.harness, t.label, t.missions_installed, t.skills_dir
                            );
                        }
                    }
                    0
                }
                Err(err) => {
                    if json {
                        println!("{}", serde_json::json!({"ok": false, "error": err}));
                    } else {
                        eprintln!("open-fleet init: {err}");
                    }
                    2
                }
            }
        }
        Commands::Doctor { repo, json } => {
            let report = of_install::doctor(&repo, ENGINE_VERSION);
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&report) {
                    println!("{s}");
                }
            } else {
                println!("open-fleet engine v{}", report.engine_version);
                println!("  binary:   {}", report.binary_path);
                if let Some(sha) = &report.binary_sha256 {
                    println!("  sha256:   {}", &sha[..16]);
                }
                println!(
                    "  git:      {}",
                    report.git_path.as_deref().unwrap_or("MISSING")
                );
                println!(
                    "  catalog:  {} ({} missions)",
                    report.catalog_root.as_deref().unwrap_or("not found"),
                    report.missions_count
                );
                println!("  runtime:  {}", report.runtime_configured);
                println!(
                    "  hooks:    claude floor-guard {}",
                    if report.claude_floor_hook_wired {
                        "wired"
                    } else {
                        "not wired (run `open-fleet init --harness claude`)"
                    }
                );
                let harnesses: Vec<String> = report.detected_harnesses.keys().cloned().collect();
                println!(
                    "  harnesses detected ({}): {}",
                    harnesses.len(),
                    if harnesses.is_empty() {
                        "none".to_string()
                    } else {
                        harnesses.join(", ")
                    }
                );
                let supported: Vec<&str> = HARNESS_PROFILES.iter().map(|h| h.id).collect();
                println!("  supported install targets: {}", supported.join(", "));
            }
            if report.ready {
                0
            } else {
                1
            }
        }
        Commands::Hook { mode, repo, rest } => match mode.as_str() {
            "floor" => of_floor::run(&FloorConfig {
                base: None,
                constraints: "CONSTRAINTS.md".to_string(),
                waivers: "docs/DECISIONS.md".to_string(),
                repo,
                quiet: true,
                json: false,
            }),
            "deny" => delegate_deny_hook(&repo, &rest),
            other => {
                eprintln!("open-fleet hook: unknown --mode {other:?} (expected 'floor' or 'deny')");
                2
            }
        },
        Commands::External(args) => delegate_python(&args),
    }
}

fn main() -> ExitCode {
    let code = run();
    ExitCode::from(code.clamp(0, 255) as u8)
}
