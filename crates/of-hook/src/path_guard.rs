//! Worktree boundary, lexical normalization, symlink-chain resolution, and glob expansion
//! for `of-hook` — native Rust port of `runtime/scripts/deny-hook.sh` `L5735-5829` & `L6690-6770`.

use crate::shlex_util::fnmatchcase;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SYMLINK_HOPS: usize = 32;
const MAX_GLOB_MATCHES: usize = 64;

const SYMLINK_CYCLE_ERR: &str =
    "deny-hook: the write target is a symlink chain over 32 links deep, or a cycle. Fail-closed.";
const UNRESOLVABLE_ERR: &str =
    "deny-hook: the write target could not be resolved to an absolute path. Fail-closed.";
const EDIT_OUTSIDE_ERR: &str = "deny-hook: this worker may only write inside its own worktree. The target resolves outside the unit boundary.";
const BASH_OUTSIDE_ERR: &str = "deny-hook: this worker may only write inside its own worktree. A shell redirect or tee destination names an absolute path outside the unit boundary.";
const GLOB_CAP_ERR: &str =
    "deny-hook: glob write target expands to more than 64 paths; fail-closed.";

fn trim_trailing_slashes(s: &str) -> &str {
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() && s.starts_with('/') {
        "/"
    } else {
        trimmed
    }
}

/// POSIX `dirname` on raw string segments (preserving `.` and `..` verbatim).
pub(crate) fn posix_dirname(s: &str) -> String {
    if s.is_empty() {
        return ".".to_string();
    }
    let t = trim_trailing_slashes(s);
    if t == "/" {
        return "/".to_string();
    }
    match t.rfind('/') {
        None => ".".to_string(),
        Some(0) => "/".to_string(),
        Some(pos) => trim_trailing_slashes(&t[..pos]).to_string(),
    }
}

/// POSIX `basename` on raw string segments (preserving `.` and `..` verbatim).
pub(crate) fn posix_basename(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let t = trim_trailing_slashes(s);
    if t == "/" {
        return "/".to_string();
    }
    match t.rfind('/') {
        None => t.to_string(),
        Some(pos) => t[pos + 1..].to_string(),
    }
}

/// Collapses `.` and `..` lexically into an absolute path without touching the filesystem
/// or performing any glob expansion on path segments.
pub fn lexical_abs(path: &str, cwd: &Path) -> PathBuf {
    let full = if path.starts_with('/') {
        path.to_string()
    } else if cwd.is_absolute() {
        format!("{}/{}", cwd.to_string_lossy(), path)
    } else {
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        format!(
            "{}/{}/{}",
            base.to_string_lossy(),
            cwd.to_string_lossy(),
            path
        )
    };

    let mut segs: Vec<&str> = Vec::new();
    for seg in full.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            other => segs.push(other),
        }
    }

    if segs.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(format!("/{}", segs.join("/")))
    }
}

/// Walks up until an existing directory is found, canonicalizes it physically, then appends
/// the remaining non-existent tail and collapses `.` / `..` via `lexical_abs`.
pub fn resolve_dir(path: &str, cwd: &Path) -> PathBuf {
    if path.is_empty() {
        return PathBuf::new();
    }
    let mut d = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", cwd.to_string_lossy(), path)
    };

    let mut tail: Vec<String> = Vec::new();
    while !Path::new(&d).is_dir() {
        let parent = posix_dirname(&d);
        if parent == d {
            break;
        }
        tail.push(posix_basename(&d));
        d = parent;
    }

    let real_base = fs::canonicalize(&d).unwrap_or_else(|_| PathBuf::from(&d));
    if tail.is_empty() {
        lexical_abs(&real_base.to_string_lossy(), cwd)
    } else {
        tail.reverse();
        let joined = format!("{}/{}", real_base.to_string_lossy(), tail.join("/"));
        lexical_abs(&joined, cwd)
    }
}

/// Resolves the physical directory holding the final target component of `path`, following
/// symlinks on the final component iteratively up to 32 hops (fail-closed on cycle/overflow).
pub fn resolve_target(path: &str, cwd: &Path) -> Result<PathBuf, String> {
    let mut base = posix_basename(path);
    let mut resolved = resolve_dir(&posix_dirname(path), cwd);
    let mut hops = 0usize;

    while !resolved.as_os_str().is_empty() {
        let candidate_str = if resolved == Path::new("/") {
            format!("/{base}")
        } else {
            format!("{}/{base}", resolved.to_string_lossy())
        };
        let is_link = fs::symlink_metadata(&candidate_str)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_link {
            break;
        }
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Err(SYMLINK_CYCLE_ERR.to_string());
        }
        let tgt = match fs::read_link(&candidate_str) {
            Ok(t) => t.to_string_lossy().into_owned(),
            Err(_) => break,
        };
        if tgt.is_empty() {
            break;
        }
        let tgt_dir = posix_dirname(&tgt);
        resolved = if tgt.starts_with('/') {
            resolve_dir(&tgt_dir, cwd)
        } else {
            resolve_dir(&format!("{}/{tgt_dir}", resolved.to_string_lossy()), cwd)
        };
        base = posix_basename(&tgt);
    }

    Ok(resolved)
}

/// Verifies a file-tool write target resolves inside `bound` (exact path component prefix).
pub fn check_edit_target(target: &str, bound: Option<&Path>, cwd: &Path) -> Result<(), String> {
    let Some(bound) = bound else {
        return Ok(());
    };
    let bound_real = fs::canonicalize(bound).unwrap_or_else(|_| bound.to_path_buf());
    let real = resolve_target(target, cwd)?;
    if real.as_os_str().is_empty() {
        return Err(UNRESOLVABLE_ERR.to_string());
    }
    if real == bound_real || real.starts_with(&bound_real) {
        Ok(())
    } else {
        Err(EDIT_OUTSIDE_ERR.to_string())
    }
}

fn is_allowed_dev_target(target: &str) -> bool {
    if matches!(
        target,
        "/dev/null"
            | "/dev/zero"
            | "/dev/full"
            | "/dev/tty"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/dev/stdin"
    ) {
        return true;
    }
    if let Some(suf) = target.strip_prefix("/dev/fd/") {
        return !suf.is_empty() && suf.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

fn expand_glob_dfs(
    dir: &Path,
    segs: &[&str],
    trailing_slash: bool,
    out: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if segs.is_empty() {
        if trailing_slash && !dir.is_dir() {
            return Ok(());
        }
        out.push(dir.to_path_buf());
        if out.len() > MAX_GLOB_MATCHES {
            return Err(GLOB_CAP_ERR.to_string());
        }
        return Ok(());
    }

    let seg = segs[0];
    let rest = &segs[1..];

    if !has_glob_meta(seg) {
        let next = dir.join(seg);
        if seg == "." || seg == ".." {
            if dir.is_dir() {
                expand_glob_dfs(&next, rest, trailing_slash, out)?;
            }
        } else if fs::symlink_metadata(&next).is_ok() {
            expand_glob_dfs(&next, rest, trailing_slash, out)?;
        }
        return Ok(());
    }

    let Ok(rd) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut names: Vec<String> = rd
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();

    for name in names {
        if name.starts_with('.') && !seg.starts_with('.') {
            continue;
        }
        if fnmatchcase(&name, seg) {
            let next = dir.join(&name);
            expand_glob_dfs(&next, rest, trailing_slash, out)?;
        }
    }
    Ok(())
}

fn expand_glob_abs(pattern: &str) -> Result<Vec<PathBuf>, String> {
    let trailing_slash = pattern.len() > 1 && pattern.ends_with('/');
    let segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    expand_glob_dfs(Path::new("/"), &segs, trailing_slash, &mut out)?;
    Ok(out)
}

fn check_bash_single(target: &str, bound: &Path, cwd: &Path) -> Result<(), String> {
    if is_allowed_dev_target(target) {
        return Ok(());
    }
    match check_edit_target(target, Some(bound), cwd) {
        Ok(()) => Ok(()),
        Err(err) if err == EDIT_OUTSIDE_ERR => Err(BASH_OUTSIDE_ERR.to_string()),
        Err(err) => Err(err),
    }
}

/// Verifies an absolute Bash redirect or `tee` destination against `bound`, allowlisting
/// standard streams/bit-bucket devices and expanding filesystem globs (capped at 64 matches).
pub fn check_bash_write_target(
    target: &str,
    bound: Option<&Path>,
    cwd: &Path,
) -> Result<(), String> {
    let Some(bound) = bound else {
        return Ok(());
    };
    if !target.starts_with('/') {
        return Ok(());
    }
    if has_glob_meta(target) {
        let matches = expand_glob_abs(target)?;
        for m in &matches {
            let ms = m.to_string_lossy();
            if ms.as_ref() == target {
                continue;
            }
            check_bash_single(&ms, bound, cwd)?;
        }
    }
    check_bash_single(target, bound, cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut rnd = [0u8; 6];
            getrandom::getrandom(&mut rnd).expect("rnd");
            let p = std::env::temp_dir().join(format!("of-pg-{tag}-{}", hex::encode(rnd)));
            fs::create_dir_all(&p).expect("mkdir");
            Self(fs::canonicalize(&p).unwrap_or(p))
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lexical_abs_collapses_dots_without_globbing() {
        let cwd = Path::new("/work/wt");
        assert_eq!(
            lexical_abs("src/../a.py", cwd),
            PathBuf::from("/work/wt/a.py")
        );
        assert_eq!(lexical_abs("/a/b/../../c", cwd), PathBuf::from("/c"));
        assert_eq!(lexical_abs("/../../../etc/x", cwd), PathBuf::from("/etc/x"));
        assert_eq!(
            lexical_abs("/work/wt/.?/.?/f", cwd),
            PathBuf::from("/work/wt/.?/.?/f")
        );
    }

    #[test]
    fn edit_target_enforces_component_prefix_and_symlink_chains() {
        let tmp = TempDir::new("edit");
        let wt = tmp.path().join("wt");
        let wt_other = tmp.path().join("wt-other");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(wt.join("src")).expect("wt");
        fs::create_dir_all(&wt_other).expect("wt-other");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(wt.join("src/a.py"), "x").expect("a");
        fs::write(outside.join("secret.py"), "y").expect("secret");

        assert!(check_edit_target(&wt.join("src/a.py").to_string_lossy(), Some(&wt), &wt).is_ok());
        assert!(check_edit_target(
            &wt.join("src/new/deep/f.py").to_string_lossy(),
            Some(&wt),
            &wt
        )
        .is_ok());
        assert!(
            check_edit_target(&wt_other.join("x.py").to_string_lossy(), Some(&wt), &wt).is_err()
        );
        assert!(
            check_edit_target("src/nonexistent/../../../outside/secret.py", Some(&wt), &wt)
                .is_err()
        );

        let mid = wt.join("src/mid.py");
        symlink(outside.join("secret.py"), &mid).expect("symlink mid");
        let head = wt.join("src/head.py");
        symlink(&mid, &head).expect("symlink head");
        assert!(check_edit_target(&head.to_string_lossy(), Some(&wt), &wt).is_err());

        let cyc_a = wt.join("src/cyc-a");
        let cyc_b = wt.join("src/cyc-b");
        symlink(&cyc_b, &cyc_a).expect("cyc a");
        symlink(&cyc_a, &cyc_b).expect("cyc b");
        let err = check_edit_target(&cyc_a.to_string_lossy(), Some(&wt), &wt).unwrap_err();
        assert!(err.contains("over 32 links deep"), "{err}");
    }

    #[test]
    fn bash_write_target_checks_dev_and_globs() {
        let tmp = TempDir::new("bash");
        let wt = tmp.path().join("wt");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&wt).expect("wt");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("secret"), "y").expect("secret");
        symlink(&outside, wt.join("link")).expect("symlink");

        assert!(check_bash_write_target("rel.txt", Some(&wt), &wt).is_ok());
        assert!(check_bash_write_target("/dev/null", Some(&wt), &wt).is_ok());
        assert!(check_bash_write_target("/dev/fd/2", Some(&wt), &wt).is_ok());
        assert!(check_bash_write_target("/dev/sda", Some(&wt), &wt).is_err());
        assert!(check_bash_write_target("/dev/fd/", Some(&wt), &wt).is_err());
        assert!(check_bash_write_target("/dev/fd/1/../../tmp/pwn", Some(&wt), &wt).is_err());

        let glob_escape = format!("{}/lin*/secret", wt.display());
        let err = check_bash_write_target(&glob_escape, Some(&wt), &wt).unwrap_err();
        assert!(err.contains("redirect"), "{err}");

        let many = wt.join("many");
        fs::create_dir_all(&many).expect("many");
        for i in 0..66 {
            fs::write(many.join(format!("f{i:02}")), "x").expect("f");
        }
        let glob_cap = format!("{}/f*", many.display());
        let cap_err = check_bash_write_target(&glob_cap, Some(&wt), &wt).unwrap_err();
        assert!(cap_err.contains("more than 64 paths"), "{cap_err}");
    }
}
