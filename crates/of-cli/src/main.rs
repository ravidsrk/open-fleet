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
use of_verify::chain_check::{
    cmd_audit as chain_audit, cmd_classify as chain_classify, cmd_gate as chain_gate,
};
use of_verify::ci_check::{
    render_step_summary as ci_render_summary, render_workflow_snippet as ci_render_snippet,
    run_ci_verify, CiCheckArgs,
};
use of_verify::diff_scope::{run_cli as diff_scope_run, DiffScopeArgs};
use of_verify::dispatch_sign::{
    cmd_sign as ds_sign, cmd_sign_transcript as ds_sign_transcript, cmd_verify as ds_verify,
    gen_key as ds_gen_key, SignArgs as DsSignArgs, SignTranscriptArgs as DsSignTranscriptArgs,
    VerifyArgs as DsVerifyArgs,
};
use of_verify::inventory::{
    cmd_check as inv_check, cmd_receipt as inv_receipt, cmd_sign as inv_sign,
    cmd_write as inv_write, ReceiptArgs as InvReceiptArgs,
};
use of_verify::preflight::run_raw_cli as preflight_run_raw;
use of_verify::proof_status::{run_cli as proof_status_run, ProofStatusArgs};
use of_verify::quarantine::{run_cli as quarantine_run, QuarantineArgs};
use of_verify::readiness::{readiness_report, run_negative_probes};
use of_verify::sessions::{
    advance_session, approve_gate, benchmark_progressive_savings, build_phase_packet,
    list_sessions, load_session, start_session, AdvanceSessionArgs, ApproveGateArgs,
    StartSessionArgs,
};
use of_verify::solo_review::{run_solo_review, SoloReviewArgs};
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
enum DispatchSignCmd {
    /// Generate an Ed25519 keypair (seed off-repo at 0600, pubkey at <out>.pub).
    #[command(name = "gen-key")]
    GenKey {
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "in-repo-ok")]
        in_repo_ok: bool,
    },
    /// Sign a dispatch record.
    Sign {
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long = "manifest-id", allow_hyphen_values = true)]
        manifest_id: String,
        #[arg(long = "contract-digest", allow_hyphen_values = true)]
        contract_digest: String,
        #[arg(long = "unit-class", allow_hyphen_values = true)]
        unit_class: String,
        #[arg(long, allow_hyphen_values = true)]
        lighting: Option<String>,
        #[arg(long = "nc-path", allow_hyphen_values = true)]
        nc_path: Vec<String>,
        #[arg(long = "nc-command", allow_hyphen_values = true)]
        nc_command: Option<String>,
        #[arg(long = "nc-artifact-sha256", allow_hyphen_values = true)]
        nc_artifact_sha256: Option<String>,
        #[arg(long = "no-gh")]
        no_gh: bool,
        #[arg(long, allow_hyphen_values = true)]
        lane: Option<String>,
        #[arg(long = "execute-nc")]
        execute_nc: bool,
        #[arg(long = "allow-static-nc")]
        allow_static_nc: bool,
        #[arg(long = "base-sha", allow_hyphen_values = true)]
        base_sha: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        profile: Option<String>,
        #[arg(long = "parent-profile", allow_hyphen_values = true)]
        parent_profile: Option<String>,
    },
    /// Verify a dispatch record and monotonic privilege narrowing.
    Verify {
        #[arg(allow_hyphen_values = true)]
        record_pos: Option<String>,
        #[arg(long, alias = "envelope", allow_hyphen_values = true)]
        record: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        pubkey: Option<String>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, allow_hyphen_values = true)]
        profile: Option<String>,
        #[arg(long = "parent-profile", allow_hyphen_values = true)]
        parent_profile: Option<String>,
    },
    /// Sign a verify.py verdict object (re-hashing toolchain.files beside the signer).
    #[command(name = "sign-transcript")]
    SignTranscript {
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        transcript: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long = "scripts-dir", hide = true)]
        scripts_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum InventoryCmd {
    /// Re-hash every listed path and rewrite the block in place.
    Write {
        report: PathBuf,
        #[arg(long = "dry-run")]
        dry_run: bool,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Re-hash every listed path that exists (or at --at REV) and optionally verify signature.
    Check {
        report: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        at: Option<String>,
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
    /// Sign the entry set with the coordinator's Ed25519 key.
    Sign {
        report: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Write the v1 retention receipt for a signed inventory.
    Receipt {
        report: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        unit: String,
        #[arg(long = "source-revision", allow_hyphen_values = true)]
        source_revision: String,
        #[arg(long = "log-index", allow_hyphen_values = true)]
        log_index: i64,
        #[arg(long = "entry-uuid", allow_hyphen_values = true)]
        entry_uuid: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ChainCheckCmd {
    /// Classify a mission terminal state (clean | degraded | handoff | unknown).
    Classify {
        #[arg(allow_hyphen_values = true)]
        terminal: String,
    },
    /// Gate a mission chain boundary against declared allowed terminals.
    Gate {
        #[arg(long, allow_hyphen_values = true)]
        allowed: String,
        #[arg(allow_hyphen_values = true)]
        terminal: String,
    },
    /// Audit every skills/*/SKILL.md terminal label against the classification rule.
    Audit {
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Start a progressive (<5K-token/phase) mission session.
    Start {
        mission: String,
        goal: Vec<String>,
        #[arg(long, default_value = "")]
        base: String,
        #[arg(long, default_value = "auto")]
        runtime: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "sessions-dir")]
        sessions_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// List progressive sessions persisted for a repo.
    List {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "sessions-dir")]
        sessions_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show the <5K-token active phase packet.
    Packet {
        session_id: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "sessions-dir")]
        sessions_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Record explicit human approval for a one-way gate (freeze, promote).
    Approve {
        session_id: String,
        #[arg(long)]
        gate: String,
        #[arg(long, allow_hyphen_values = true)]
        actor: String,
        #[arg(long, allow_hyphen_values = true)]
        rationale: String,
        #[arg(long = "contract-digest", default_value = "")]
        contract_digest: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "sessions-dir")]
        sessions_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Advance a progressive session by one phase (fail-closed).
    Advance {
        session_id: String,
        #[arg(long)]
        ok: bool,
        #[arg(long = "receipt-json", default_value = "", allow_hyphen_values = true)]
        receipt_json: String,
        #[arg(long, default_value = "", allow_hyphen_values = true)]
        terminal: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "sessions-dir")]
        sessions_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Measure <5K-token progressive savings across all catalog missions.
    Benchmark {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        json: bool,
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
    /// Classify the changed surface into SCOPE_* review flags, overlap specs, or predict 3-way merges.
    #[command(name = "diff-scope")]
    DiffScope {
        #[arg(long, allow_hyphen_values = true)]
        base: Option<String>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        overlap: Option<PathBuf>,
        #[arg(long = "predict-merge", num_args = 2, value_names = ["BASE", "BRANCH"], allow_hyphen_values = true)]
        predict_merge: Option<Vec<String>>,
        #[arg(long)]
        json: bool,
    },
    /// Check the catalog or one mission against runtime/quarantine.json (fail-closed off-switch).
    Quarantine {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, conflicts_with = "mission")]
        catalog: bool,
        #[arg(long, allow_hyphen_values = true)]
        mission: Option<String>,
    },
    /// Coordinator out-of-band Ed25519 dispatch-record & transcript signer.
    #[command(name = "dispatch-sign")]
    DispatchSign {
        #[command(subcommand)]
        sub: DispatchSignCmd,
    },
    /// Regenerate, check, Ed25519-sign, and issue v1 retention receipts for run integrity inventories.
    Inventory {
        #[command(subcommand)]
        sub: InventoryCmd,
    },
    /// Proof-posture reporter and CI lens over the mission catalog.
    #[command(name = "proof-status")]
    ProofStatus {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        check: bool,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Fail-closed Phase-0 preflight invariants (capabilities, quarantine, BASE != default branch).
    #[command(disable_help_flag = true)]
    Preflight {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Mission-chaining degraded-terminal classifier, gate, and catalog auditor.
    #[command(name = "chain-check")]
    ChainCheck {
        #[command(subcommand)]
        sub: ChainCheckCmd,
    },
    /// Progressive (<5K-token/phase) mission state machines with enforced human gates.
    Session {
        #[command(subcommand)]
        sub: SessionCmd,
    },
    /// Honest solo-developer verified review lane (native diff-scope + floor-guard + blind packet).
    #[command(name = "solo-review")]
    SoloReview {
        #[arg(long, default_value = "origin/main", allow_hyphen_values = true)]
        base: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long, default_value = "")]
        contract: String,
        #[arg(long, default_value = "")]
        builder: String,
        #[arg(long, default_value = "")]
        manifest: String,
        #[arg(long, default_value = "auto")]
        lighting: String,
        #[arg(long = "nc-command", default_value = "", allow_hyphen_values = true)]
        nc_command: String,
        #[arg(long = "with-gh")]
        with_gh: bool,
        #[arg(long = "transcript-out", default_value = "")]
        transcript_out: String,
        #[arg(long = "transcript-key", default_value = "")]
        transcript_key: String,
        #[arg(long = "packet-out", default_value = "")]
        packet_out: String,
        #[arg(long)]
        json: bool,
    },
    /// Composable PR verification gate (native floor-guard + diff-scope + optional verify.py).
    #[command(name = "ci-check")]
    CiCheck {
        #[arg(long, default_value = "origin/main", allow_hyphen_values = true)]
        base: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "skip-floor")]
        skip_floor: bool,
        #[arg(long = "skip-scope")]
        skip_scope: bool,
        #[arg(long = "strict-scope")]
        strict_scope: bool,
        #[arg(long = "fail-on-risk-lenses")]
        fail_on_risk_lenses: bool,
        #[arg(long, default_value = "")]
        manifest: String,
        #[arg(long = "contract-source", default_value = "")]
        contract_source: String,
        #[arg(long = "contract-digest", default_value = "")]
        contract_digest: String,
        #[arg(long = "execute-nc")]
        execute_nc: bool,
        #[arg(long = "nc-command", default_value = "", allow_hyphen_values = true)]
        nc_command: String,
        #[arg(long = "allow-static-nc")]
        allow_static_nc: bool,
        #[arg(long = "no-gh")]
        no_gh: bool,
        #[arg(long = "workflow-snippet")]
        workflow_snippet: bool,
        #[arg(long = "workflow-base", default_value = "main")]
        workflow_base: String,
        #[arg(long = "with-manifest-example")]
        with_manifest_example: bool,
        #[arg(long)]
        json: bool,
    },
    /// Honest proof-graduation & multi-harness certification readiness workbench.
    Readiness {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "check-cert")]
        check_cert: bool,
        #[arg(long)]
        probes: bool,
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
        Commands::DiffScope {
            base,
            repo,
            strict,
            overlap,
            predict_merge,
            json,
        } => {
            let pm = predict_merge.and_then(|v| {
                if v.len() == 2 {
                    Some((v[0].clone(), v[1].clone()))
                } else {
                    None
                }
            });
            diff_scope_run(&DiffScopeArgs {
                base,
                repo,
                strict,
                overlap,
                predict_merge: pm,
                json,
            })
        }
        Commands::Quarantine {
            root,
            catalog,
            mission,
        } => quarantine_run(&QuarantineArgs {
            root,
            catalog,
            mission,
        }),
        Commands::DispatchSign { sub } => match sub {
            DispatchSignCmd::GenKey { out, in_repo_ok } => ds_gen_key(&out, in_repo_ok),
            DispatchSignCmd::Sign {
                key,
                manifest_id,
                contract_digest,
                unit_class,
                lighting,
                nc_path,
                nc_command,
                nc_artifact_sha256,
                no_gh,
                lane,
                execute_nc,
                allow_static_nc,
                base_sha,
                profile,
                parent_profile,
            } => ds_sign(&DsSignArgs {
                key,
                manifest_id,
                contract_digest,
                unit_class,
                lighting,
                nc_paths: if nc_path.is_empty() {
                    None
                } else {
                    Some(nc_path)
                },
                nc_command,
                nc_artifact_sha256,
                no_gh,
                lane,
                execute_nc,
                allow_static_nc,
                base_sha,
                profile,
                parent_profile,
            }),
            DispatchSignCmd::Verify {
                record_pos,
                record,
                pubkey,
                key,
                profile,
                parent_profile,
            } => ds_verify(&DsVerifyArgs {
                record_ref: record.or(record_pos),
                pubkey_ref: pubkey,
                key_ref: key,
                profile,
                parent_profile,
            }),
            DispatchSignCmd::SignTranscript {
                key,
                transcript,
                out,
                scripts_dir,
            } => ds_sign_transcript(&DsSignTranscriptArgs {
                key,
                transcript,
                out,
                scripts_dir,
            }),
        },
        Commands::Inventory { sub } => match sub {
            InventoryCmd::Write {
                report,
                dry_run,
                key,
            } => inv_write(&report, dry_run, key.as_deref()),
            InventoryCmd::Check { report, at, pubkey } => {
                inv_check(&report, at.as_deref(), pubkey.as_deref())
            }
            InventoryCmd::Sign { report, key } => inv_sign(&report, &key),
            InventoryCmd::Receipt {
                report,
                key,
                unit,
                source_revision,
                log_index,
                entry_uuid,
                out,
            } => inv_receipt(&InvReceiptArgs {
                report,
                key,
                unit,
                source_revision,
                log_index,
                entry_uuid,
                out,
            }),
        },
        Commands::ProofStatus { json, check, root } => {
            proof_status_run(&ProofStatusArgs { json, check, root })
        }
        Commands::Preflight { args } => preflight_run_raw(&args),
        Commands::ChainCheck { sub } => match sub {
            ChainCheckCmd::Classify { terminal } => chain_classify(&terminal),
            ChainCheckCmd::Gate { allowed, terminal } => chain_gate(&allowed, &terminal),
            ChainCheckCmd::Audit { root } => chain_audit(root.as_deref()),
        },
        Commands::Session { sub } => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match sub {
                SessionCmd::Benchmark { repo, json } => {
                    let target = repo.unwrap_or(cwd);
                    let root = match require_catalog(&target) {
                        Ok(r) => r,
                        Err(code) => return code,
                    };
                    let bench = benchmark_progressive_savings(&root);
                    if json {
                        if let Ok(s) = serde_json::to_string_pretty(&bench) {
                            println!("{s}");
                        }
                    } else {
                        println!(
                            "Progressive Phase Budget Benchmark ({} missions · ceiling={} tok · avg reduction={}%)",
                            bench.get("mission_count").and_then(|v| v.as_u64()).unwrap_or(0),
                            bench.get("ceiling_tokens").and_then(|v| v.as_u64()).unwrap_or(5000),
                            bench.get("avg_reduction_pct").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        );
                    }
                    if bench
                        .get("all_within_ceiling")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        0
                    } else {
                        1
                    }
                }
                SessionCmd::List {
                    repo,
                    sessions_dir,
                    json,
                } => {
                    let target = repo.unwrap_or(cwd);
                    let items = list_sessions(&target, sessions_dir.as_deref());
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({"sessions": items}))
                                .unwrap_or_else(|_| "{}".to_string())
                        );
                    } else if items.is_empty() {
                        println!("No progressive sessions yet. Start one with: open-fleet session start <mission> \"<goal>\"");
                    } else {
                        for it in &items {
                            println!(
                                "{}  [{}]  mission={}  phase={}  terminal={}",
                                it.get("session_id").and_then(|v| v.as_str()).unwrap_or(""),
                                it.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                                it.get("mission").and_then(|v| v.as_str()).unwrap_or(""),
                                it.get("current_phase")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(""),
                                it.get("terminal_state")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("—"),
                            );
                        }
                    }
                    0
                }
                SessionCmd::Start {
                    mission,
                    goal,
                    base,
                    runtime,
                    repo,
                    sessions_dir,
                    json,
                } => {
                    let target = repo.unwrap_or(cwd);
                    let root = match require_catalog(&target) {
                        Ok(r) => r,
                        Err(code) => return code,
                    };
                    let goal_s = goal.join(" ");
                    match start_session(&StartSessionArgs {
                        mission: &mission,
                        goal: &goal_s,
                        root: &root,
                        repo: &target,
                        sessions_dir: sessions_dir.as_deref(),
                        base_branch: &base,
                        runtime: &runtime,
                    }) {
                        Ok(res) => {
                            if json {
                                if let Ok(s) = serde_json::to_string_pretty(&res) {
                                    println!("{s}");
                                }
                            } else {
                                let pkt = &res["packet"];
                                println!(
                                    "Started session: {}  (mission={} · phase={})",
                                    pkt["session_id"].as_str().unwrap_or(""),
                                    pkt["mission"].as_str().unwrap_or(""),
                                    pkt["phase"]["id"].as_str().unwrap_or(""),
                                );
                            }
                            0
                        }
                        Err(err) => {
                            if json {
                                println!("{}", serde_json::json!({"ok": false, "error": err}));
                            } else {
                                eprintln!("open-fleet session: FAIL: {err}");
                            }
                            1
                        }
                    }
                }
                SessionCmd::Packet {
                    session_id,
                    repo,
                    sessions_dir,
                    json,
                } => {
                    let target = repo.unwrap_or(cwd);
                    let root = match require_catalog(&target) {
                        Ok(r) => r,
                        Err(code) => return code,
                    };
                    match load_session(&session_id, &target, sessions_dir.as_deref()) {
                        Ok(st) => {
                            let pkt = build_phase_packet(&st, &root);
                            if json {
                                if let Ok(s) = serde_json::to_string_pretty(&pkt) {
                                    println!("{s}");
                                }
                            } else {
                                println!(
                                    "Session {} · mission={} · phase={}",
                                    pkt["session_id"].as_str().unwrap_or(""),
                                    pkt["mission"].as_str().unwrap_or(""),
                                    pkt["phase"]["id"].as_str().unwrap_or(""),
                                );
                            }
                            0
                        }
                        Err(err) => {
                            if json {
                                println!("{}", serde_json::json!({"ok": false, "error": err}));
                            } else {
                                eprintln!("open-fleet session: FAIL: {err}");
                            }
                            1
                        }
                    }
                }
                SessionCmd::Approve {
                    session_id,
                    gate,
                    actor,
                    rationale,
                    contract_digest,
                    repo,
                    sessions_dir,
                    json,
                } => {
                    let target = repo.unwrap_or(cwd);
                    let root = match require_catalog(&target) {
                        Ok(r) => r,
                        Err(code) => return code,
                    };
                    match approve_gate(&ApproveGateArgs {
                        session_id: &session_id,
                        gate: &gate,
                        actor: &actor,
                        rationale: &rationale,
                        contract_digest: &contract_digest,
                        root: &root,
                        repo: &target,
                        sessions_dir: sessions_dir.as_deref(),
                    }) {
                        Ok(res) => {
                            if json {
                                if let Ok(s) = serde_json::to_string_pretty(&res) {
                                    println!("{s}");
                                }
                            } else {
                                println!(
                                    "Approved gate '{}' by {}",
                                    res["approval"]["gate"].as_str().unwrap_or(""),
                                    res["approval"]["actor"].as_str().unwrap_or(""),
                                );
                            }
                            0
                        }
                        Err(err) => {
                            if json {
                                println!("{}", serde_json::json!({"ok": false, "error": err}));
                            } else {
                                eprintln!("open-fleet session: FAIL: {err}");
                            }
                            1
                        }
                    }
                }
                SessionCmd::Advance {
                    session_id,
                    ok,
                    receipt_json,
                    terminal,
                    repo,
                    sessions_dir,
                    json,
                } => {
                    let target = repo.unwrap_or(cwd);
                    let root = match require_catalog(&target) {
                        Ok(r) => r,
                        Err(code) => return code,
                    };
                    let rec = if !receipt_json.trim().is_empty() {
                        match serde_json::from_str::<serde_json::Value>(&receipt_json) {
                            Ok(serde_json::Value::Object(m)) => Some(m),
                            _ => {
                                eprintln!(
                                    "open-fleet session: FAIL: receipt must be a JSON object"
                                );
                                return 1;
                            }
                        }
                    } else if ok {
                        let mut m = serde_json::Map::new();
                        m.insert("ok".to_string(), serde_json::Value::Bool(true));
                        Some(m)
                    } else {
                        None
                    };
                    match advance_session(&AdvanceSessionArgs {
                        session_id: &session_id,
                        receipt: rec,
                        terminal_state: &terminal,
                        root: &root,
                        repo: &target,
                        sessions_dir: sessions_dir.as_deref(),
                    }) {
                        Ok(res) => {
                            if json {
                                if let Ok(s) = serde_json::to_string_pretty(&res) {
                                    println!("{s}");
                                }
                            } else if res.get("closed").and_then(|v| v.as_bool()).unwrap_or(false) {
                                println!(
                                    "Closed session {}: terminal={} ({})",
                                    session_id,
                                    res["session"]["terminal_state"].as_str().unwrap_or(""),
                                    res["session"]["terminal_class"].as_str().unwrap_or(""),
                                );
                            } else {
                                println!(
                                    "Advanced {}: {} -> {}",
                                    session_id,
                                    res["from_phase"].as_str().unwrap_or(""),
                                    res["to_phase"].as_str().unwrap_or(""),
                                );
                            }
                            0
                        }
                        Err(err) => {
                            if json {
                                println!("{}", serde_json::json!({"ok": false, "error": err}));
                            } else {
                                eprintln!("open-fleet session: FAIL: {err}");
                            }
                            1
                        }
                    }
                }
            }
        }
        Commands::SoloReview {
            base,
            repo,
            contract,
            builder,
            manifest,
            lighting,
            nc_command,
            with_gh,
            transcript_out,
            transcript_key,
            packet_out,
            json,
        } => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let target = repo.unwrap_or(cwd);
            let root = match require_catalog(&target) {
                Ok(r) => r,
                Err(code) => return code,
            };
            match run_solo_review(&SoloReviewArgs {
                base,
                root,
                repo: target,
                contract_path: contract,
                builder_harness: builder,
                manifest,
                lighting,
                nc_command,
                no_gh: !with_gh,
                transcript_out,
                transcript_key,
                packet_out,
            }) {
                Ok(res) => {
                    let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if json {
                        if let Ok(s) = serde_json::to_string_pretty(&res) {
                            println!("{s}");
                        }
                    } else {
                        println!(
                            "open-fleet solo-review ({}) · base={}",
                            res["review_mode"].as_str().unwrap_or(""),
                            res["base"].as_str().unwrap_or(""),
                        );
                        println!(
                            "Floor guard:  {}",
                            if res["floor_guard"]["ok"].as_bool().unwrap_or(false) {
                                "CLEAN"
                            } else {
                                "FAIL"
                            }
                        );
                        println!(
                            "Lighting:     {} — {}",
                            res["lighting"]["effective"].as_str().unwrap_or(""),
                            res["lighting"]["reason"].as_str().unwrap_or(""),
                        );
                    }
                    if ok {
                        0
                    } else {
                        1
                    }
                }
                Err(err) => {
                    if json {
                        println!("{}", serde_json::json!({"ok": false, "error": err}));
                    } else {
                        eprintln!("open-fleet solo-review: FAIL: {err}");
                    }
                    1
                }
            }
        }
        Commands::CiCheck {
            base,
            repo,
            skip_floor,
            skip_scope,
            strict_scope,
            fail_on_risk_lenses,
            manifest,
            contract_source,
            contract_digest,
            execute_nc,
            nc_command,
            allow_static_nc,
            no_gh,
            workflow_snippet,
            workflow_base,
            with_manifest_example,
            json,
        } => {
            if workflow_snippet {
                print!(
                    "{}",
                    ci_render_snippet(&workflow_base, with_manifest_example)
                );
                return 0;
            }
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let target = repo.unwrap_or(cwd);
            let root = match require_catalog(&target) {
                Ok(r) => r,
                Err(code) => return code,
            };
            match run_ci_verify(&CiCheckArgs {
                base,
                root,
                repo: target,
                run_floor_guard: !skip_floor,
                run_diff_scope: !skip_scope,
                strict_scope,
                fail_on_risk_lenses,
                manifest,
                contract_source,
                contract_digest,
                execute_nc,
                nc_command,
                allow_static_nc,
                no_gh,
            }) {
                Ok(res) => {
                    let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if json {
                        if let Ok(s) = serde_json::to_string_pretty(&res) {
                            println!("{s}");
                        }
                    } else {
                        println!("{}", ci_render_summary(&res));
                    }
                    if ok {
                        0
                    } else {
                        1
                    }
                }
                Err(err) => {
                    if json {
                        println!("{}", serde_json::json!({"ok": false, "error": err}));
                    } else {
                        eprintln!("open-fleet ci-check: FAIL: {err}");
                    }
                    1
                }
            }
        }
        Commands::Readiness {
            repo,
            check_cert,
            probes,
            json,
        } => {
            let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let target = repo.unwrap_or(cwd);
            let root = match require_catalog(&target) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let mut rep = readiness_report(&root, ENGINE_VERSION, check_cert);
            let cert_ok = rep
                .get("certification_check")
                .and_then(|v| v.get("ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut probes_ok = true;
            if probes {
                let pr = run_negative_probes(&root);
                probes_ok = pr.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                if let Some(obj) = rep.as_object_mut() {
                    obj.insert("negative_probes".to_string(), pr);
                }
            }
            if json {
                if let Ok(s) = serde_json::to_string_pretty(&rep) {
                    println!("{s}");
                }
            } else {
                println!(
                    "open-fleet readiness · proven={}/{} · binding_runs={}",
                    rep["proven_count"].as_u64().unwrap_or(0),
                    rep["total_missions"].as_u64().unwrap_or(0),
                    rep["binding_runs_count"].as_u64().unwrap_or(0),
                );
            }
            if cert_ok && probes_ok {
                0
            } else {
                1
            }
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
