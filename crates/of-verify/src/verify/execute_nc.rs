//! Executed negative-control harness — native Rust port of `verify.py`'s
//! `_apply_control` and `execute_negative_control` (#255, #279, #280, #629, #750 C19, #768).

use crate::verify::authority::{
    devnull, normpath_str, pathlib_posix, python_module_target, run_proc_bytes,
    staged_script_operands, unreplayable_tool, verify_staged_rel_file, PinnedExecRec, VerifyCtx,
    ABSENT_GIT,
};
use crate::verify::diff::{
    bind_hunks_to_change, diff_target_paths, extract_diff, hunk_lines, is_hex40, nc_paths,
    shlex_join,
};
use crate::verify::sig::failure_signature;
use crate::verify::{
    bind_paths_to_change, changed_paths, nc_command_argv, read_artifact, EvidenceManifest,
    EXECUTABLE_NC_TOOLS,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const NC_TIMEOUT_S: u64 = 600;

fn run_at_text(
    cwd: &Path,
    argv: &[OsString],
    timeout_s: u64,
    stdin_bytes: Option<&[u8]>,
    env_vec: &[(OsString, OsString)],
) -> (i32, String, String) {
    if argv.is_empty() {
        return (124, String::new(), ABSENT_GIT.to_string());
    }
    let prog = Path::new(&argv[0]);
    let (code, out_b, err) =
        run_proc_bytes(prog, &argv[1..], Some(cwd), env_vec, stdin_bytes, timeout_s);
    (code, String::from_utf8_lossy(&out_b).into_owned(), err)
}

fn git_argv(ctx: &VerifyCtx, args: &[&str]) -> Result<Vec<OsString>, String> {
    let Some(git) = ctx.git_bin.as_deref() else {
        return Err(ABSENT_GIT.to_string());
    };
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push(git.as_os_str().to_os_string());
    for a in args {
        out.push(OsString::from(a));
    }
    Ok(out)
}

fn unsigned_commit(raw: &[u8]) -> Vec<u8> {
    let split = raw.windows(2).position(|w| w == b"\n\n");
    let (header, rest) = match split {
        Some(pos) => (&raw[..pos], &raw[pos..]),
        None => (raw, &[][..]),
    };
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut skipping = false;
    for line in header.split(|&b| b == b'\n') {
        if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            skipping = true;
            continue;
        }
        if skipping && line.starts_with(b" ") {
            continue;
        }
        skipping = false;
        kept.push(line);
    }
    let mut out = kept.join(&b'\n');
    out.extend_from_slice(rest);
    out
}

fn tag_kind(raw: &[u8]) -> Option<(&'static str, String)> {
    let nl = raw.iter().position(|&b| b == b'\n')?;
    if !raw.starts_with(b"object ") {
        return None;
    }
    let obj_s = String::from_utf8_lossy(&raw[7..nl]).into_owned();
    if !is_hex40(&obj_s) {
        return None;
    }
    let after = &raw[nl + 1..];
    let next_nl = after
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(after.len());
    let line = &after[..next_nl];
    if line == b"type commit" {
        Some(("commit", obj_s))
    } else if line == b"type tag" {
        Some(("tag", obj_s))
    } else {
        None
    }
}

fn unsigned_tag(raw: &[u8]) -> Vec<u8> {
    let split = raw.windows(2).position(|w| w == b"\n\n");
    let (header, sep, body) = match split {
        Some(pos) => (&raw[..pos], &b"\n\n"[..], &raw[pos + 2..]),
        None => (raw, &[][..], &[][..]),
    };
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut skipping = false;
    for line in header.split(|&b| b == b'\n') {
        if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            skipping = true;
            continue;
        }
        if skipping && line.starts_with(b" ") {
            continue;
        }
        skipping = false;
        kept.push(line);
    }
    let body_lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
    let cut = body_lines
        .iter()
        .position(|ln| {
            ln.starts_with(b"-----BEGIN PGP SIGNATURE-----")
                || ln.starts_with(b"-----BEGIN SSH SIGNATURE-----")
        })
        .unwrap_or(body_lines.len());
    let mut out = kept.join(&b'\n');
    out.extend_from_slice(sep);
    out.extend_from_slice(&body_lines[..cut].join(&b'\n'));
    out
}

fn retarget_tag(
    ctx: &VerifyCtx,
    top: &Path,
    repo: &Path,
    tag_sha: &str,
    commit: &str,
    seen: &mut HashSet<String>,
) -> Result<String, String> {
    if !seen.insert(tag_sha.to_string()) || seen.len() >= 8 {
        return Err("annotated tag chain is cyclic or too deep".to_string());
    }
    let git = ctx
        .git_bin
        .as_deref()
        .ok_or_else(|| ABSENT_GIT.to_string())?;
    let env_vec = ctx.git_env();
    let argv = vec![
        OsString::from("-C"),
        top.as_os_str().to_os_string(),
        OsString::from("cat-file"),
        OsString::from("tag"),
        OsString::from(tag_sha),
    ];
    let (code, raw, gerr) = run_proc_bytes(git, &argv, None, &env_vec, None, 30);
    let Some((kind, obj)) = (if code == 0 { tag_kind(&raw) } else { None }) else {
        let msg = gerr.trim();
        return Err(if msg.is_empty() {
            "not an annotated tag of a commit or a tag".to_string()
        } else {
            msg.to_string()
        });
    };
    let clean = unsigned_tag(&raw);
    let new_obj = if kind == "tag" {
        retarget_tag(ctx, top, repo, &obj, commit, seen)?
    } else {
        commit.to_string()
    };
    let nl = clean
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| "annotated tag lost its object line".to_string())?;
    if !clean.starts_with(b"object ") {
        return Err("annotated tag lost its object line".to_string());
    }
    let mut rewritten = b"object ".to_vec();
    rewritten.extend_from_slice(new_obj.as_bytes());
    rewritten.extend_from_slice(&clean[nl..]);
    let ho_argv = git_argv(ctx, &["hash-object", "-t", "tag", "-w", "--stdin"])?;
    let (hcode, hout, herr) = run_at_text(repo, &ho_argv, 20, Some(&rewritten), &env_vec);
    let new_sha = hout.trim().to_string();
    if hcode != 0 || !is_hex40(&new_sha) {
        let msg = herr.trim();
        return Err(if msg.is_empty() {
            "could not write the retargeted tag".to_string()
        } else {
            msg.to_string()
        });
    }
    Ok(new_sha)
}

fn apply_control(
    ctx: &mut VerifyCtx,
    wt: &Path,
    m: &mut EvidenceManifest,
    nc: &Value,
    tool: &str,
    nc_command: Option<&str>,
) -> Result<(), String> {
    if tool == "revert" {
        let base = m
            .data
            .get("base_sha")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (paths_opt, perr) = nc_paths(nc, |p| ctx.resolve_evidence(p));
        if let Some(e) = perr {
            return Err(e);
        }
        if let Some(paths) = paths_opt {
            if !is_hex40(base) {
                return Err(
                    "negative_control.paths needs a pinned 40-hex base_sha to restore the pre-fix content from"
                        .to_string(),
                );
            }
            if let Some(be) =
                bind_paths_to_change(ctx, &paths, m, "negative_control.paths", nc_command)
            {
                return Err(be);
            }
            let blanks = ctx.driver_blanks(wt)?;
            let mut argv = git_argv(ctx, &["--literal-pathspecs", "checkout", base, "--"])?;
            for p in &paths {
                argv.push(OsString::from(p));
            }
            let (code, _, gerr) = run_at_text(wt, &argv, 20, None, &ctx.blanked_env(&blanks));
            if code != 0 {
                return Err(format!(
                    "could not restore {paths:?} from base_sha in the control worktree: {}",
                    gerr.trim()
                ));
            }
            let diff_argv = git_argv(
                ctx,
                &[
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    "HEAD",
                ],
            )?;
            let (dcode, actual, derr) = run_at_text(wt, &diff_argv, 20, None, &ctx.git_env());
            if dcode != 0 {
                return Err(format!("cannot inspect restored paths: {}", derr.trim()));
            }
            let affected: BTreeSet<String> = actual
                .trim_end_matches('\0')
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            let declared: BTreeSet<String> = paths.iter().cloned().collect();
            if affected != declared {
                let aff_v: Vec<&str> = affected.iter().map(|s| s.as_str()).collect();
                let dec_v: Vec<&str> = declared.iter().map(|s| s.as_str()).collect();
                return Err(format!(
                    "restored paths {aff_v:?} differ from declared paths {dec_v:?}"
                ));
            }
            let aff_list: Vec<String> = affected.into_iter().collect();
            if let Some(be) =
                bind_paths_to_change(ctx, &aff_list, m, "the applied revert", nc_command)
            {
                return Err(be);
            }
            return Ok(());
        }
        // Range revert fallback
        let head = m
            .data
            .get("head_sha")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_hex40(base) || !is_hex40(head) {
            return Err(
                "negative_control.paths is required for tool 'revert' (the range fallback needs pinned base_sha and head_sha)"
                    .to_string(),
            );
        }
        let anc_argv = git_argv(ctx, &["merge-base", "--is-ancestor", base, head])?;
        if run_at_text(wt, &anc_argv, 20, None, &ctx.git_env()).0 != 0 {
            return Err(
                "negative_control.paths is required: base_sha..head_sha is not linear (base is not an ancestor of head), so a range revert is not well-defined"
                    .to_string(),
            );
        }
        let range = format!("{base}..{head}");
        let m_argv = git_argv(ctx, &["rev-list", "--merges", &range])?;
        let (mcode, merges, _) = run_at_text(wt, &m_argv, 20, None, &ctx.git_env());
        if mcode != 0 || !merges.trim().is_empty() {
            return Err(
                "negative_control.paths is required: base_sha..head_sha contains merge commits, so a range revert is not well-defined"
                    .to_string(),
            );
        }
        let (_prod, tests) = changed_paths(ctx, base, head, nc_command)?;
        if !tests.is_empty() {
            let mut sorted_t = tests;
            sorted_t.sort();
            return Err(format!(
                "negative_control.paths is REQUIRED here: base_sha..head_sha changes test paths ({sorted_t:?}), and a range revert would remove them along with the fix. The bound command would then go RED because its oracle is gone, not because the behaviour came back. Name the production paths the control should restore (#280)"
            ));
        }
        let blanks = ctx.driver_blanks(wt)?;
        let rev_argv = git_argv(ctx, &["revert", "--no-commit", &range])?;
        let (rcode, _, rerr) = run_at_text(wt, &rev_argv, 60, None, &ctx.blanked_env(&blanks));
        if rcode != 0 {
            return Err(format!(
                "git revert of base_sha..head_sha failed in the control worktree: {}",
                rerr.trim()
            ));
        }
        return Ok(());
    }

    // tool == "hand" or diff-carrying mutation tool
    let art = nc.get("artifact").and_then(|v| v.as_str()).unwrap_or("");
    let raw = read_artifact(ctx, m, art).map_err(|e| {
        format!("negative_control.artifact unreadable, so the hand mutant cannot be applied: {e}")
    })?;
    let diff = extract_diff(&String::from_utf8_lossy(&raw)).ok_or_else(|| {
        "negative_control.artifact for tool 'hand' quotes no applicable unified diff".to_string()
    })?;
    let targets = diff_target_paths(&diff, |p| ctx.resolve_evidence(p))?;
    if targets.is_empty() {
        return Err(
            "negative_control.artifact for tool 'hand' quotes a diff with no `+++` target — nothing identifies which file the mutant touches, so it cannot be bound to the change (#280)"
                .to_string(),
        );
    }
    if let Some(be) = bind_paths_to_change(ctx, &targets, m, "the hand mutant's diff", nc_command) {
        return Err(be);
    }
    if let Some(he) = bind_hunks_to_change(
        &diff,
        &m.data,
        m.oracle_scope.as_ref(),
        |p| ctx.resolve_evidence(p),
        |a| ctx.git_str(a, 10),
    ) {
        return Err(he);
    }
    let blanks = ctx.driver_blanks(wt)?;
    let apply_argv = git_argv(ctx, &["apply", "--index", "--whitespace=nowarn", "-"])?;
    let (acode, _, aerr) = run_at_text(
        wt,
        &apply_argv,
        20,
        Some(diff.as_bytes()),
        &ctx.blanked_env(&blanks),
    );
    if acode != 0 {
        return Err(format!(
            "the hand mutant quoted in negative_control.artifact does not apply at head_sha ({}) — the quoted diff is not the diff that was run",
            aerr.trim()
        ));
    }
    let inspect_argv = git_argv(
        ctx,
        &[
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "-U0",
            "HEAD",
        ],
    )?;
    let (icode, actual, ierr) = run_at_text(wt, &inspect_argv, 20, None, &ctx.git_env());
    if icode != 0 {
        return Err(format!(
            "cannot inspect applied mutant coordinates: {}",
            ierr.trim()
        ));
    }
    let actual_targets = diff_target_paths(&actual, |p| ctx.resolve_evidence(p))?;
    let actual_hunks = hunk_lines(&actual, '-')?;
    let quoted_hunks = hunk_lines(&diff, '-')?;
    if actual_targets != targets || actual_hunks != quoted_hunks {
        return Err(
            "applied mutant paths/coordinates differ from the quoted control (possible hunk relocation)"
                .to_string(),
        );
    }
    if let Some(be) = bind_paths_to_change(
        ctx,
        &actual_targets,
        m,
        "the applied hand mutant",
        nc_command,
    ) {
        return Err(be);
    }
    if let Some(he) = bind_hunks_to_change(
        &actual,
        &m.data,
        m.oracle_scope.as_ref(),
        |p| ctx.resolve_evidence(p),
        |a| ctx.git_str(a, 10),
    ) {
        return Err(he);
    }
    Ok(())
}

fn seal_control(
    ctx: &mut VerifyCtx,
    wt: &Path,
    head: &str,
    m: &EvidenceManifest,
    nc_command: Option<&str>,
) -> Result<(String, String), String> {
    let blanks = ctx.driver_blanks(wt)?;
    let wt_argv = git_argv(ctx, &["write-tree"])?;
    let (code, tree_out, gerr) = run_at_text(wt, &wt_argv, 20, None, &ctx.blanked_env(&blanks));
    let tree = tree_out.trim().to_string();
    if code != 0 || !is_hex40(&tree) {
        return Err(format!(
            "cannot record the applied control's tree: {}",
            gerr.trim()
        ));
    }
    let head_tree = ctx.tree_of(head).unwrap_or_default();
    if tree == head_tree {
        return Err(
            "the negative control changed NOTHING at head_sha — a no-op mutant cannot make any proof go RED (#255)"
                .to_string(),
        );
    }
    let dt_argv = git_argv(
        ctx,
        &[
            "diff-tree",
            "-r",
            "-z",
            "--name-only",
            "--no-renames",
            &head_tree,
            &tree,
        ],
    )?;
    let (dcode, sealed, derr) = run_at_text(wt, &dt_argv, 20, None, &ctx.git_env());
    if dcode != 0 {
        return Err(format!(
            "cannot list what the sealed control changes: {}",
            derr.trim()
        ));
    }
    let sealed_paths: Vec<String> = sealed
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if let Some(be) = bind_paths_to_change(ctx, &sealed_paths, m, "the sealed control", nc_command)
    {
        return Err(be);
    }
    let (ccode, raw, cerr) = ctx.git_bytes(&["cat-file", "commit", head], 20);
    let nl = raw.iter().position(|&b| b == b'\n');
    if ccode != 0 || !raw.starts_with(b"tree ") || nl.is_none() {
        return Err(format!(
            "cannot read head_sha's commit object to seal the control: {}",
            cerr.trim()
        ));
    }
    let unsigned_raw = unsigned_commit(&raw);
    let env_vec = ctx.git_env();
    let ho_argv = git_argv(ctx, &["hash-object", "-t", "commit", "-w", "--stdin"])?;
    let clean = if unsigned_raw != raw {
        let (ucode, uout, uerr) = run_at_text(wt, &ho_argv, 20, Some(&unsigned_raw), &env_vec);
        let c = uout.trim().to_string();
        if ucode != 0 || !is_hex40(&c) {
            return Err(format!(
                "cannot seal unsigned clean commit: {}",
                uerr.trim()
            ));
        }
        c
    } else {
        head.to_string()
    };
    let u_nl = unsigned_raw
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(unsigned_raw.len());
    let mut sibling = b"tree ".to_vec();
    sibling.extend_from_slice(tree.as_bytes());
    sibling.extend_from_slice(&unsigned_raw[u_nl..]);
    let (mcode, mout, merr) = run_at_text(wt, &ho_argv, 20, Some(&sibling), &env_vec);
    let mutant = mout.trim().to_string();
    if mcode != 0 || !is_hex40(&mutant) {
        return Err(format!(
            "cannot commit the applied control as a throwaway commit: {}",
            merr.trim()
        ));
    }
    Ok((clean, mutant))
}

fn prepare_control(
    ctx: &mut VerifyCtx,
    top: &Path,
    head: &str,
    m: &mut EvidenceManifest,
    nc: &Value,
    tool: &str,
    nc_command: Option<&str>,
) -> Result<(String, String), String> {
    let holder = tempfile::Builder::new()
        .prefix("orca-nc-")
        .tempdir()
        .map_err(|e| format!("could not create the control worktree at head_sha: {e}"))?;
    let wt = holder.path().join("wt");
    let custody = ctx
        .control_git_dir(top, head)
        .map_err(|e| format!("could not create the control worktree at head_sha: {e}"))?;
    fs::create_dir(&wt)
        .map_err(|e| format!("could not create the control worktree at head_sha: {e}"))?;
    let gitfile = format!("gitdir: {}\n", custody.path.display());
    fs::write(wt.join(".git"), gitfile.as_bytes())
        .map_err(|e| format!("could not create the control worktree at head_sha: {e}"))?;

    let blanks = ctx.driver_blanks(&wt).map_err(|fail| {
        format!(
            "cannot read the control worktree's driver config, so its filter and merge commands cannot be neutralised ({fail}); fail-closed"
        )
    })?;
    let co_argv = git_argv(ctx, &["checkout", "-q", "--detach", head])?;
    let (code, _, gerr) = run_at_text(&wt, &co_argv, 120, None, &ctx.blanked_env(&blanks));
    if code != 0 {
        return Err(format!(
            "could not populate the control worktree at head_sha: {}",
            gerr.trim()
        ));
    }
    apply_control(ctx, &wt, m, nc, tool, nc_command)?;
    seal_control(ctx, &wt, head, m, nc_command)
}

fn stage_phase_repo(
    ctx: &VerifyCtx,
    top: &Path,
    head: &str,
    commit: &str,
    repo: &Path,
    phase: &str,
) -> Result<(), String> {
    let git = ctx
        .git_bin
        .as_deref()
        .ok_or_else(|| ABSENT_GIT.to_string())?;
    let env_vec = ctx.git_env();
    let run_g = |args: &[OsString], timeout_s: u64| -> (i32, String, String) {
        let (c, o, e) = run_proc_bytes(git, args, None, &env_vec, None, timeout_s);
        (c, String::from_utf8_lossy(&o).into_owned(), e)
    };
    let (code, _, gerr) = run_g(
        &[
            OsString::from("init"),
            OsString::from("-q"),
            repo.as_os_str().to_os_string(),
        ],
        60,
    );
    if code != 0 {
        return Err(format!(
            "could not create the {phase} repository: {}",
            gerr.trim()
        ));
    }
    let (ccode, common, cerr) = run_g(
        &[
            OsString::from("-C"),
            top.as_os_str().to_os_string(),
            OsString::from("rev-parse"),
            OsString::from("--git-common-dir"),
        ],
        30,
    );
    if ccode != 0 {
        return Err(format!(
            "could not locate the source object store for the {phase} repository: {}",
            cerr.trim()
        ));
    }
    let mut common_path = PathBuf::from(common.trim());
    if !common_path.is_absolute() {
        common_path = top.join(common_path);
    }
    let objects = fs::canonicalize(common_path.join("objects"))
        .unwrap_or_else(|_| common_path.join("objects"));
    let obj_s = objects.to_string_lossy().into_owned();
    if obj_s.contains('\n') || obj_s.contains('\r') || obj_s.contains('\0') {
        return Err(format!(
            "cannot stage the {phase} repository: object store path contains control/newline bytes"
        ));
    }
    let alt = repo.join(".git/objects/info/alternates");
    if let Some(p) = alt.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = objects.as_os_str().as_bytes().to_vec();
        bytes.push(b'\n');
        fs::write(&alt, bytes).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&alt, format!("{obj_s}\n")).map_err(|e| e.to_string())?;
    }

    let (scode, sym, _) = run_g(
        &[
            OsString::from("-C"),
            top.as_os_str().to_os_string(),
            OsString::from("symbolic-ref"),
            OsString::from("-q"),
            OsString::from("HEAD"),
        ],
        30,
    );
    let sym_ref = sym.trim();
    if scode == 0 && sym_ref.starts_with("refs/heads/") {
        let (uc, _, ue) = run_g(
            &[
                OsString::from("-C"),
                repo.as_os_str().to_os_string(),
                OsString::from("update-ref"),
                OsString::from(sym_ref),
                OsString::from(commit),
            ],
            30,
        );
        if uc != 0 {
            return Err(format!(
                "could not copy {sym_ref} into the {phase} repository: {}",
                ue.trim()
            ));
        }
        let (hc, _, he) = run_g(
            &[
                OsString::from("-C"),
                repo.as_os_str().to_os_string(),
                OsString::from("symbolic-ref"),
                OsString::from("HEAD"),
                OsString::from(sym_ref),
            ],
            30,
        );
        if hc != 0 {
            return Err(format!(
                "could not set HEAD in the {phase} repository: {}",
                he.trim()
            ));
        }
    }

    let (lc, listing, le) = run_g(
        &[
            OsString::from("-C"),
            top.as_os_str().to_os_string(),
            OsString::from("for-each-ref"),
            OsString::from("--format=%(refname)"),
            OsString::from("refs/tags/"),
        ],
        60,
    );
    if lc != 0 {
        return Err(format!(
            "could not read the source tag refs for the {phase} repository: {}",
            le.trim()
        ));
    }
    for ref_name in listing.split('\n').filter(|r| !r.is_empty()) {
        let (dc, direct_s, de) = run_g(
            &[
                OsString::from("-C"),
                top.as_os_str().to_os_string(),
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(ref_name),
            ],
            30,
        );
        if dc != 0 {
            return Err(format!(
                "could not resolve {ref_name} for the {phase} repository: {}",
                de.trim()
            ));
        }
        let direct = direct_s.trim();
        let (pc, peeled_s, _) = run_g(
            &[
                OsString::from("-C"),
                top.as_os_str().to_os_string(),
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(format!("{ref_name}^{{commit}}")),
            ],
            30,
        );
        let peeled = if pc == 0 { peeled_s.trim() } else { "" };
        if direct != head && peeled != head {
            continue;
        }
        let target = if direct == commit {
            direct.to_string()
        } else if peeled == head && direct != head {
            let mut seen = HashSet::new();
            retarget_tag(ctx, top, repo, direct, commit, &mut seen).map_err(|e| {
                format!("could not retarget {ref_name} in the {phase} repository: {e}")
            })?
        } else {
            commit.to_string()
        };
        let (uc, _, ue) = run_g(
            &[
                OsString::from("-C"),
                repo.as_os_str().to_os_string(),
                OsString::from("update-ref"),
                OsString::from(ref_name),
                OsString::from(target),
            ],
            30,
        );
        if uc != 0 {
            return Err(format!(
                "could not copy {ref_name} into the {phase} repository: {}",
                ue.trim()
            ));
        }
    }

    let dn = devnull();
    let (rc, _, re) = run_g(
        &[
            OsString::from("-C"),
            repo.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from(format!("core.attributesFile={dn}")),
            OsString::from("-c"),
            OsString::from(format!("core.excludesFile={dn}")),
            OsString::from("reset"),
            OsString::from("--hard"),
            OsString::from("--quiet"),
            OsString::from(commit),
        ],
        120,
    );
    if rc != 0 {
        return Err(format!(
            "could not check out the {phase} commit: {}",
            re.trim()
        ));
    }
    Ok(())
}

struct PhaseRunSpec<'a> {
    top: &'a Path,
    head: &'a str,
    commit: &'a str,
    phase: &'a str,
    argv: &'a [String],
    pinned_exec: &'a [PinnedExecRec],
    extra_staged_ops: &'a [String],
    absent_mod_paths: &'a [String],
}

fn phase_run(ctx: &VerifyCtx, spec: &PhaseRunSpec<'_>) -> Result<(i32, String, String), String> {
    let PhaseRunSpec {
        top,
        head,
        commit,
        phase,
        argv,
        pinned_exec,
        extra_staged_ops,
        absent_mod_paths,
    } = *spec;
    let holder = tempfile::Builder::new()
        .prefix("orca-nc-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let repo = holder.path().join("repo");
    let home = holder.path().join("home");
    let tmp = holder.path().join("tmp");
    fs::create_dir(&home).map_err(|e| e.to_string())?;
    fs::create_dir(&tmp).map_err(|e| e.to_string())?;

    let mut env_vec: Vec<(OsString, OsString)> = ctx
        .nc_env()
        .into_iter()
        .filter(|(k, _)| !matches!(k.to_str(), Some("HOME" | "TMPDIR" | "TMP" | "TEMP")))
        .collect();
    let path_str = env_vec
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    env_vec.push((OsString::from("HOME"), home.as_os_str().to_os_string()));
    env_vec.push((OsString::from("TMPDIR"), tmp.as_os_str().to_os_string()));
    env_vec.push((OsString::from("TMP"), tmp.as_os_str().to_os_string()));
    env_vec.push((OsString::from("TEMP"), tmp.as_os_str().to_os_string()));

    stage_phase_repo(ctx, top, head, commit, &repo, phase)?;

    let mut staged_ops: Vec<String> = Vec::new();
    let mut seen_ops: HashSet<String> = HashSet::new();
    for op in staged_script_operands(argv)
        .into_iter()
        .chain(extra_staged_ops.iter().cloned())
    {
        if seen_ops.insert(op.clone()) {
            staged_ops.push(op);
        }
    }
    let mut pre_op_digests: BTreeMap<String, String> = BTreeMap::new();
    for s_op in &staged_ops {
        let dig = verify_staged_rel_file(&repo, s_op)?;
        pre_op_digests.insert(s_op.clone(), dig);
    }
    for abs_rel in absent_mod_paths {
        if fs::symlink_metadata(repo.join(abs_rel)).is_ok() {
            return Err(format!(
                "proof module shadow {abs_rel:?} appeared before {phase}; fail-closed (#750 C19)"
            ));
        }
    }

    let _ = ctx.nc_exec_identity(
        argv,
        Some(top),
        Some(&path_str),
        Some(pinned_exec),
        Some(&format!("before {phase}")),
    )?;
    let mut exec_argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    for rec in pinned_exec {
        if rec.argv_idx < exec_argv.len() && !Path::new(&argv[rec.argv_idx]).is_absolute() {
            exec_argv[rec.argv_idx] = OsString::from(&rec.self_rec.abs_path);
        }
    }
    let (rc, out, errout) = run_at_text(&repo, &exec_argv, NC_TIMEOUT_S, None, &env_vec);

    for (s_op, want_digest) in &pre_op_digests {
        let post_digest = verify_staged_rel_file(&repo, s_op)?;
        if &post_digest != want_digest {
            return Err(format!(
                "proof input {s_op:?} changed during {phase}; fail-closed (#750 C19)"
            ));
        }
    }
    for abs_rel in absent_mod_paths {
        if fs::symlink_metadata(repo.join(abs_rel)).is_ok() {
            return Err(format!(
                "proof module shadow {abs_rel:?} appeared during {phase}; fail-closed (#750 C19)"
            ));
        }
    }
    let _ = ctx.nc_exec_identity(
        argv,
        Some(top),
        Some(&path_str),
        Some(pinned_exec),
        Some(&format!("during {phase}")),
    )?;

    Ok((rc, out, errout))
}

pub fn execute_negative_control(
    ctx: &mut VerifyCtx,
    m: &mut EvidenceManifest,
    nc_command: Option<&str>,
) -> (bool, Vec<String>) {
    let nc = m
        .data
        .get("negative_control")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let tool = nc.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let raw_art = nc
        .get("artifact")
        .and_then(|v| v.as_str())
        .and_then(|a| read_artifact(ctx, m, a).ok());
    if !EXECUTABLE_NC_TOOLS.contains(&tool) || unreplayable_tool(tool, raw_art.as_deref()) {
        return (
            false,
            vec![format!(
                "--execute-nc: no replay is implemented for negative_control.tool {tool:?} — only {EXECUTABLE_NC_TOOLS:?} can be re-executed here; fail-closed (#255)"
            )],
        );
    }
    let head = m
        .data
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !is_hex40(&head) {
        return (
            false,
            vec!["--execute-nc: head_sha must be a pinned 40-hex commit to check out a control worktree".to_string()],
        );
    }
    let Some(top) = ctx.toplevel() else {
        return (
            false,
            vec![
                "--execute-nc: not inside a git repo — cannot create a control worktree"
                    .to_string(),
            ],
        );
    };
    let spec = format!("{head}^{{commit}}");
    if ctx.git_str(&["cat-file", "-e", &spec], 10).0 != 0 {
        return (
            false,
            vec![format!(
                "--execute-nc: head_sha '{head}' is not a real commit here"
            )],
        );
    }
    let argv = match nc_command_argv(ctx, &nc, nc_command) {
        Ok(a) => a,
        Err(e) => return (false, vec![format!("--execute-nc: {e}")]),
    };
    let pinned_exec = match ctx.nc_exec_identity(&argv, Some(&top), None, None, None) {
        Ok(p) => p,
        Err(e) => return (false, vec![format!("--execute-nc: {e}")]),
    };

    let mut extra_staged_ops: Vec<String> = Vec::new();
    let mut absent_mod_paths: Vec<String> = Vec::new();
    if let Some(py_mod) = python_module_target(&argv) {
        let mod_parts: Vec<&str> = py_mod.split('.').collect();
        let mod_rel = mod_parts.join("/");
        let entry_cands = [format!("{mod_rel}.py"), format!("{mod_rel}/__main__.py")];
        let pkg_cands: Vec<String> = (1..=mod_parts.len())
            .map(|k| format!("{}/__init__.py", mod_parts[..k].join("/")))
            .collect();
        let mut all_cands: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for c in entry_cands.iter().chain(pkg_cands.iter()) {
            if seen.insert(c.clone()) {
                all_cands.push(c.clone());
            }
        }
        let git = ctx.git_bin.as_deref();
        let mut tracked_mods: HashMap<String, String> = HashMap::new();
        if let Some(g) = git {
            let mut ls_argv = vec![
                OsString::from("-C"),
                top.as_os_str().to_os_string(),
                OsString::from("--literal-pathspecs"),
                OsString::from("ls-tree"),
                OsString::from("-r"),
                OsString::from("-z"),
                OsString::from(&head),
                OsString::from("--"),
            ];
            for c in &all_cands {
                ls_argv.push(OsString::from(c));
            }
            let (ls_rc, ls_out_b, _) = run_proc_bytes(g, &ls_argv, None, &ctx.git_env(), None, 10);
            if ls_rc == 0 {
                let ls_out = String::from_utf8_lossy(&ls_out_b);
                for rec_line in ls_out.split('\0') {
                    if let Some((meta, rel_p)) = rec_line.split_once('\t') {
                        let mode = meta.split_whitespace().next().unwrap_or("");
                        if mode == "100644" || mode == "100755" {
                            tracked_mods.insert(rel_p.to_string(), mode.to_string());
                        }
                    }
                }
            }
        }
        if !entry_cands.iter().any(|ec| tracked_mods.contains_key(ec)) {
            return (
                false,
                vec![format!(
                    "--execute-nc: unsupported proof command: module '-m {py_mod}' is not a tracked regular file in head_sha; fail-closed (#750 C19)"
                )],
            );
        }
        let main_py = format!("{mod_rel}/__main__.py");
        let init_py = format!("{mod_rel}/__init__.py");
        if !tracked_mods.contains_key(&main_py) && tracked_mods.contains_key(&init_py) {
            return (
                false,
                vec![format!(
                    "--execute-nc: unsupported proof command: package '{init_py}' shadows '{mod_rel}.py' without __main__.py; fail-closed (#750 C19)"
                )],
            );
        }
        let req_len = mod_parts.len() - usize::from(!tracked_mods.contains_key(&main_py));
        for k in 1..=req_len {
            let rp = format!("{}/__init__.py", mod_parts[..k].join("/"));
            if !tracked_mods.contains_key(&rp) {
                return (
                    false,
                    vec![format!(
                        "--execute-nc: unsupported proof command: package hierarchy for '-m {py_mod}' is missing tracked __init__.py in head_sha; fail-closed (#750 C19)"
                    )],
                );
            }
        }
        for c in &all_cands {
            if tracked_mods.contains_key(c) {
                extra_staged_ops.push(c.clone());
            } else {
                absent_mod_paths.push(c.clone());
            }
        }
        for k in 1..mod_parts.len() {
            let sib = format!("{}.py", mod_parts[..k].join("/"));
            if !tracked_mods.contains_key(&sib) {
                absent_mod_paths.push(sib);
            }
        }
    }

    for st_op in staged_script_operands(&argv) {
        let norm_st_op = pathlib_posix(&normpath_str(&st_op));
        if Path::new(&st_op).is_absolute()
            || norm_st_op.is_empty()
            || norm_st_op == "."
            || Path::new(&norm_st_op)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return (
                false,
                vec![format!(
                    "--execute-nc: proof input {st_op:?} is not a tracked regular file in head_sha; fail-closed (#750 C19)"
                )],
            );
        }
        let Some(g) = ctx.git_bin.as_deref() else {
            return (false, vec![format!("--execute-nc: {ABSENT_GIT}")]);
        };
        let ls_argv = vec![
            OsString::from("-C"),
            top.as_os_str().to_os_string(),
            OsString::from("--literal-pathspecs"),
            OsString::from("ls-tree"),
            OsString::from(&head),
            OsString::from("--"),
            OsString::from(&norm_st_op),
        ];
        let (ls_rc, ls_out_b, _) = run_proc_bytes(g, &ls_argv, None, &ctx.git_env(), None, 10);
        let ls_out = String::from_utf8_lossy(&ls_out_b);
        let mode = ls_out.split_whitespace().next().unwrap_or("");
        if ls_rc != 0 || (mode != "100644" && mode != "100755") {
            return (
                false,
                vec![format!(
                    "--execute-nc: proof input {st_op:?} is not a tracked regular file in head_sha; fail-closed (#750 C19)"
                )],
            );
        }
    }

    let (clean, mutant) = match prepare_control(ctx, &top, &head, m, &nc, tool, nc_command) {
        Ok(pair) => pair,
        Err(e) => return (false, vec![format!("--execute-nc: {e}")]),
    };

    let mut msgs: Vec<String> = Vec::new();
    for (phase, commit) in [
        ("clean", clean.as_str()),
        ("control", mutant.as_str()),
        ("clean", clean.as_str()),
    ] {
        let (rc, out, errout) = match phase_run(
            ctx,
            &PhaseRunSpec {
                top: &top,
                head: &head,
                commit,
                phase,
                argv: &argv,
                pinned_exec: &pinned_exec,
                extra_staged_ops: &extra_staged_ops,
                absent_mod_paths: &absent_mod_paths,
            },
        ) {
            Ok(r) => r,
            Err(e) => return (false, vec![format!("--execute-nc: {e}")]),
        };
        let raw_tail = if !errout.trim().is_empty() {
            errout.trim()
        } else {
            out.trim()
        };
        let tail: String = raw_tail
            .chars()
            .rev()
            .take(300)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if phase == "clean" {
            if rc != 0 {
                let when = if msgs.is_empty() { "before" } else { "after" };
                return (
                    false,
                    vec![format!(
                        "--execute-nc: the bound command exits {rc} at CLEAN head_sha ({when} the control run), so a RED under the control is not evidence of anything: {tail}"
                    )],
                );
            }
            if !msgs.is_empty() {
                msgs.push(
                    "NOTE: the same command exits 0 at clean head_sha, before AND after the control run — the RED above is the control's doing, not a broken suite or a first-run side effect"
                        .to_string(),
                );
            }
            continue;
        }
        if rc == 124 {
            return (
                false,
                vec![format!(
                    "--execute-nc: the bound command did not complete under the control ({NC_TIMEOUT_S}s timeout / exec error): {tail}"
                )],
            );
        }
        if rc == 0 {
            return (
                false,
                vec![format!(
                    "--execute-nc: TAUTOLOGICAL — the proof does NOT go RED. The control was applied at head_sha and `{}` still exited 0, so the command does not bind to the change it claims to prove (#255)",
                    shlex_join(&argv)
                )],
            );
        }
        let (sig_ok, sig_err) = failure_signature(&out, &errout);
        if !sig_ok {
            return (
                false,
                vec![format!(
                    "--execute-nc: {} Output was: {tail}",
                    sig_err.unwrap_or_default()
                )],
            );
        }
        msgs.push(format!(
            "NOTE: negative control EXECUTED — with the {tool} control applied at head_sha the bound command exited {rc} on an assertion failure (RED, as required)"
        ));
    }
    (true, msgs)
}
