//! `open-fleet` — native Rust engine binary with strangler-fig delegation for not-yet-ported verbs.

use clap::{Parser, Subcommand};
use of_catalog::{
    catalog_overview, certification_summary, get_mission, list_missions, route_intent,
};
use of_floor::FloorConfig;
use of_install::{InstallConfig, HARNESS_PROFILES};
use of_ledgers::decisions_cli::{
    cmd_active as dec_active, cmd_append as dec_append, cmd_check as dec_check,
    cmd_grant_keygen as dec_grant_keygen, cmd_sign_grant as dec_sign_grant, cmd_tally as dec_tally,
    default_decisions_path, AppendArgs as DecAppendArgs, CheckArgs as DecCheckArgs,
    SignGrantArgs as DecSignGrantArgs,
};
use of_ledgers::egress::{
    cmd_grants as eg_grants, cmd_head as eg_head, cmd_verify as eg_verify, cmd_write as eg_write,
    GrantsArgs as EgGrantsArgs, VerifyArgs as EgVerifyArgs, WriteArgs as EgWriteArgs,
};
use of_mcp::{serve_stdio, OpenFleetMcpServer};
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
enum EgressCmd {
    /// Append one receipt BEFORE the send; prints its id, an anchor.
    Write {
        #[arg(long, allow_hyphen_values = true)]
        sink: String,
        #[arg(long, allow_hyphen_values = true)]
        host: String,
        #[arg(long = "payload-class", allow_hyphen_values = true)]
        payload_class: String,
        #[arg(long, allow_hyphen_values = true)]
        consent: String,
        #[arg(long, allow_hyphen_values = true)]
        bytes: Option<i64>,
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
        #[arg(long = "payload-sha256", allow_hyphen_values = true)]
        payload_sha256: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        ts: Option<String>,
    },
    /// Recompute the hash chain and check any anchors.
    Verify {
        #[arg(long, hide = true)]
        json: bool,
        #[arg(long = "expect-head", allow_hyphen_values = true)]
        expect_head: Option<String>,
        #[arg(long = "expect-ancestor", allow_hyphen_values = true)]
        expect_ancestor: Vec<String>,
        #[arg(long = "allow-empty")]
        allow_empty: bool,
        #[arg(long = "require-receipts")]
        require_receipts: bool,
    },
    /// Verify, then print the chain head to anchor off the writer.
    Head,
    /// Verify (with verify's anchors), then list the standing consents the ledger records.
    Grants {
        #[arg(long)]
        json: bool,
        #[arg(long = "expect-head", allow_hyphen_values = true)]
        expect_head: Option<String>,
        #[arg(long = "expect-ancestor", allow_hyphen_values = true)]
        expect_ancestor: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DecisionsCmd {
    /// Validate and append one decision line.
    Append {
        #[arg(long, allow_hyphen_values = true)]
        id: String,
        #[arg(long = "class", allow_hyphen_values = true)]
        klass: String,
        #[arg(long, allow_hyphen_values = true)]
        answer: String,
        #[arg(long, allow_hyphen_values = true)]
        why: String,
        #[arg(long, allow_hyphen_values = true)]
        task: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        source: Option<String>,
        #[arg(long = "grant-sig", allow_hyphen_values = true)]
        grant_sig: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        ts: Option<String>,
    },
    /// List non-superseded standing decisions.
    Active {
        #[arg(long)]
        json: bool,
    },
    /// Zero-finding dispatch streak for a lens.
    Tally {
        #[arg(long, allow_hyphen_values = true)]
        lens: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate an existing DECISIONS log.
    Check {
        #[arg(long, allow_hyphen_values = true)]
        since: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        base: Option<String>,
    },
    /// Generate the human grant keypair (seed off-repo).
    #[command(name = "grant-keygen")]
    GrantKeygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "in-repo-ok")]
        in_repo_ok: bool,
    },
    /// Print the Ed25519 grant signature for one decision line.
    #[command(name = "sign-grant")]
    SignGrant {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        id: String,
        #[arg(long, allow_hyphen_values = true)]
        answer: String,
        #[arg(long, allow_hyphen_values = true)]
        why: String,
        #[arg(long, allow_hyphen_values = true)]
        task: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        source: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        ts: Option<String>,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Diff-scoped floor guard: block suppressed checkers, skipped tests, deleted assertions, lowered thresholds, and guard-surface edits.
    Floor {
        #[arg(long)]
        base: Option<String>,
        #[arg(long, default_value = "CONSTRAINTS.md")]
        constraints: String,
        #[arg(long, default_value = "docs/DECISIONS.md")]
        waivers: String,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        quiet: bool,
        #[arg(long)]
        json: bool,
    },
    /// Content-free, SHA-256 hash-chained receipts for off-repo sends.
    Egress {
        #[arg(long, global = true)]
        ledger: Option<PathBuf>,
        #[command(subcommand)]
        sub: EgressCmd,
    },
    /// Append to, read, validate, and Ed25519-sign the DECISIONS ledger.
    Decisions {
        #[arg(long, global = true)]
        file: Option<PathBuf>,
        #[arg(long, global = true)]
        doors: Option<PathBuf>,
        #[arg(long = "pin-ref", global = true, allow_hyphen_values = true)]
        pin_ref: Option<String>,
        #[command(subcommand)]
        sub: DecisionsCmd,
    },
    /// List outcome-named missions from the catalog.
    Missions {
        #[arg(long)]
        proof: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Route a natural-language engineering goal to the best-matching mission + launch prompt.
    Route {
        /// Engineering goal text.
        goal: Vec<String>,
        #[arg(long = "top-k", default_value_t = 5)]
        top_k: usize,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show a single mission's identity contract, composed protocols, and launch prompt.
    Show {
        mission: String,
        #[arg(long)]
        body: bool,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Summarize provider & harness certification tiers.
    Certification {
        #[arg(long)]
        provider: Option<String>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show high-level catalog telemetry (missions, proof ladder, quarantine, pins).
    Overview {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Start the native zero-Python MCP JSON-RPC 2.0 stdio server.
    Mcp {
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Install open-fleet skills and native hooks into your coding agent harness(es).
    #[command(alias = "install")]
    Init {
        #[arg(long, default_value = "claude")]
        harness: String,
        #[arg(long, default_value = "user")]
        scope: String,
        #[arg(long, default_value = "symlink")]
        mode: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        with_hooks: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Check engine binary, git, catalog, runtime mode, and installed agent harnesses.
    Doctor {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run a guardrail hook (`floor` runs natively; `deny` delegates to deny-hook.sh).
    Hook {
        #[arg(long, default_value = "floor")]
        mode: String,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<OsString>,
    },
    /// Delegate remaining verbs (verify, events, queue, ui, demo, ...) to the catalog Python runtime.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

fn default_home() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn require_catalog(repo: &Path) -> Result<PathBuf, i32> {
    of_install::find_catalog_root(repo).ok_or_else(|| {
        eprintln!(
            "open-fleet: could not locate open-fleet catalog (skills/ + runtime/); pass --repo or set OPEN_FLEET_ROOT"
        );
        2
    })
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
        Commands::Egress { ledger, sub } => match sub {
            EgressCmd::Write {
                sink,
                host,
                payload_class,
                consent,
                bytes,
                payload_file,
                payload_sha256,
                ts,
            } => eg_write(&EgWriteArgs {
                ledger,
                sink,
                host,
                payload_class,
                consent,
                bytes,
                payload_file,
                payload_sha256,
                ts,
            }),
            EgressCmd::Verify {
                json: _,
                expect_head,
                expect_ancestor,
                allow_empty,
                require_receipts: _,
            } => eg_verify(&EgVerifyArgs {
                ledger,
                expect_head,
                expect_ancestor,
                allow_empty,
            }),
            EgressCmd::Head => eg_head(ledger.as_deref()),
            EgressCmd::Grants {
                json,
                expect_head,
                expect_ancestor,
            } => eg_grants(&EgGrantsArgs {
                ledger,
                json,
                expect_head,
                expect_ancestor,
            }),
        },
        Commands::Decisions {
            file,
            doors,
            pin_ref,
            sub,
        } => {
            let log_file = default_decisions_path(file.as_deref());
            match sub {
                DecisionsCmd::Append {
                    id,
                    klass,
                    answer,
                    why,
                    task,
                    source,
                    grant_sig,
                    ts,
                } => dec_append(&DecAppendArgs {
                    file: log_file,
                    doors,
                    pin_ref,
                    id,
                    klass,
                    answer,
                    why,
                    task,
                    source,
                    grant_sig,
                    ts,
                }),
                DecisionsCmd::Active { json } => dec_active(&log_file, pin_ref.as_deref(), json),
                DecisionsCmd::Tally { lens, json } => dec_tally(&log_file, &lens, json),
                DecisionsCmd::Check { since, base } => dec_check(&DecCheckArgs {
                    file: log_file,
                    doors,
                    pin_ref,
                    since,
                    base,
                }),
                DecisionsCmd::GrantKeygen { out, in_repo_ok } => dec_grant_keygen(&out, in_repo_ok),
                DecisionsCmd::SignGrant {
                    key,
                    id,
                    answer,
                    why,
                    task,
                    source,
                    ts,
                } => dec_sign_grant(&DecSignGrantArgs {
                    key,
                    id,
                    answer,
                    why,
                    task,
                    source,
                    ts,
                }),
            }
        }
        Commands::Missions {
            proof,
            category,
            repo,
            json,
        } => {
            let root = match require_catalog(&repo) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let missions = list_missions(&root, proof.as_deref(), category.as_deref(), false);
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&missions) {
                    println!("{s}");
                }
            } else {
                println!(
                    "open-fleet missions ({} found, catalog {}):",
                    missions.len(),
                    root.display()
                );
                for m in &missions {
                    println!(
                        "  {:18} [{:13}] {:28} {}",
                        m.name, m.proof, m.category, m.summary
                    );
                }
            }
            0
        }
        Commands::Route {
            goal,
            top_k,
            repo,
            json,
        } => {
            let root = match require_catalog(&repo) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let prompt = goal.join(" ");
            let res = route_intent(&root, &prompt, top_k);
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&res) {
                    println!("{s}");
                }
            } else if let Some(best) = &res.recommended {
                println!(
                    "recommended: {} [{}] (score={:.4}, evidence={:.4})",
                    best.mission, best.proof, best.score, best.evidence
                );
                println!("\n{}\n", best.launch_prompt);
                if res.matches.len() > 1 {
                    println!("alternatives:");
                    for m in &res.matches[1..] {
                        println!(
                            "  - {:18} [{:13}] score={:.4} evidence={:.4}",
                            m.mission, m.proof, m.score, m.evidence
                        );
                    }
                }
            } else {
                println!(
                    "no mission met the evidence floor ({:.2}) for {:?}",
                    res.min_evidence, res.query
                );
                for m in &res.matches {
                    println!(
                        "  - {:18} [{:13}] score={:.4} evidence={:.4}",
                        m.mission, m.proof, m.score, m.evidence
                    );
                }
            }
            0
        }
        Commands::Show {
            mission,
            body,
            repo,
            json,
        } => {
            let root = match require_catalog(&repo) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let Some(mut m) = get_mission(&root, &mission) else {
                eprintln!("open-fleet show: unknown mission {mission:?}");
                return 2;
            };
            if !body {
                m.body = None;
            }
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&m) {
                    println!("{s}");
                }
            } else {
                println!("{} [{}] — {}", m.name, m.proof, m.category);
                println!("  summary:     {}", m.summary);
                println!("  unit:        {}", m.identity.unit);
                println!("  convergence: {}", m.identity.convergence);
                println!("  oracle:      {}", m.identity.oracle);
                if let Some(lp) = &m.launch_prompt {
                    println!("\nLaunch prompt:\n{lp}");
                }
            }
            0
        }
        Commands::Certification {
            provider,
            repo,
            json,
        } => {
            let root = match require_catalog(&repo) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let mut summary = certification_summary(&root);
            if let Some(pname) = provider.as_deref() {
                if let Some(arr) = summary.get("providers").and_then(|v| v.as_array()).cloned() {
                    let filtered: Vec<serde_json::Value> = arr
                        .into_iter()
                        .filter(|p| p.get("name").and_then(|n| n.as_str()) == Some(pname))
                        .collect();
                    if let Some(obj) = summary.as_object_mut() {
                        obj.insert("providers".to_string(), serde_json::Value::Array(filtered));
                    }
                }
            }
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&summary) {
                    println!("{s}");
                }
            } else if let Some(arr) = summary.get("providers").and_then(|v| v.as_array()) {
                println!("open-fleet certification ({} provider(s)):", arr.len());
                for p in arr {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let live = p
                        .get("cell_counts")
                        .and_then(|c| c.get("live-witnessed"))
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0);
                    let fix = p
                        .get("cell_counts")
                        .and_then(|c| c.get("fixture-tested"))
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0);
                    println!("  - {name:16} live-witnessed={live} fixture-tested={fix}");
                }
            }
            0
        }
        Commands::Overview { repo, json } => {
            let root = match require_catalog(&repo) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let ov = catalog_overview(&root);
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&ov) {
                    println!("{s}");
                }
            } else {
                println!(
                    "open-fleet catalog v{} ({} missions, {} live-witnessed cells)",
                    ov.get("version").and_then(|v| v.as_str()).unwrap_or("?"),
                    ov.get("mission_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    ov.get("live_witnessed_cells")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
            }
            0
        }
        Commands::Mcp { root, repo } => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let target_repo = repo.unwrap_or_else(|| cwd.clone());
            let catalog_root = match root {
                Some(r) => r,
                None => match require_catalog(&target_repo) {
                    Ok(r) => r,
                    Err(code) => return code,
                },
            };
            let server = OpenFleetMcpServer::new(catalog_root, target_repo);
            serve_stdio(&server)
        }
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
