//! Embedded canonical Markdown catalog and atomic materializer.
//!
//! Allows the standalone `open-fleet` binary to run zero-clone outside any git
//! checkout by extracting the compile-time embedded catalog (`skills/`,
//! `playbooks/`, `runtime/*.md`, JSON metadata, retained run index, and UI HTML)
//! once into `~/.open-fleet/catalog/<version>-<sha12>/`.

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/embedded_catalog.rs"));

const STAMP_FILE: &str = ".embedded-catalog-complete";

pub fn embedded_file_count() -> usize {
    EMBEDDED_FILES.len()
}

pub fn embedded_file(rel: &str) -> Option<&'static [u8]> {
    EMBEDDED_FILES
        .binary_search_by_key(&rel, |(k, _)| *k)
        .ok()
        .map(|idx| EMBEDDED_FILES[idx].1)
}

pub fn default_cache_base() -> PathBuf {
    if let Ok(explicit) = env::var("OPEN_FLEET_CACHE_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    home.join(".open-fleet")
}

fn validate_rel_path(rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(format!("embedded path must be relative: {rel}"));
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(seg) => clean.push(seg),
            _ => return Err(format!("unsafe embedded catalog path: {rel}")),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("empty embedded catalog path".to_string());
    }
    Ok(clean)
}

fn expected_stamp(engine_version: &str) -> String {
    format!("{engine_version}:{EMBEDDED_CATALOG_SHA256}\n")
}

fn is_materialized(target: &Path, stamp: &str) -> bool {
    if !target.join("skills").is_dir() || !target.join("runtime").is_dir() {
        return false;
    }
    fs::read_to_string(target.join(STAMP_FILE))
        .map(|s| s == stamp)
        .unwrap_or(false)
}

/// Materialize the embedded catalog into `<cache_base>/catalog/<version>-<sha12>/`.
///
/// Idempotent and concurrency-safe: if the version+digest stamp already matches,
/// returns immediately without writing any files. Otherwise stages into a sibling
/// temp directory and atomically renames into place.
pub fn materialize_catalog(
    cache_base: Option<&Path>,
    engine_version: &str,
) -> Result<PathBuf, String> {
    if EMBEDDED_FILES.is_empty() {
        return Err("embedded catalog is empty in this binary build".to_string());
    }
    let base = cache_base
        .map(Path::to_path_buf)
        .unwrap_or_else(default_cache_base);
    let sha12 = &EMBEDDED_CATALOG_SHA256[..12.min(EMBEDDED_CATALOG_SHA256.len())];
    let catalog_parent = base.join("catalog");
    let target = catalog_parent.join(format!("{engine_version}-{sha12}"));
    let stamp = expected_stamp(engine_version);

    if is_materialized(&target, &stamp) {
        return Ok(target);
    }

    fs::create_dir_all(&catalog_parent)
        .map_err(|e| format!("mkdir {}: {e}", catalog_parent.display()))?;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stage = catalog_parent.join(format!(".staging-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&stage).map_err(|e| format!("mkdir {}: {e}", stage.display()))?;

    let write_res: Result<(), String> = (|| {
        for (rel, bytes) in EMBEDDED_FILES {
            let clean = validate_rel_path(rel)?;
            let dst = stage.join(&clean);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            }
            fs::write(&dst, bytes).map_err(|e| format!("write {}: {e}", dst.display()))?;
        }
        fs::write(stage.join(STAMP_FILE), &stamp)
            .map_err(|e| format!("write {}: {e}", stage.join(STAMP_FILE).display()))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_dir_all(&stage);
        return Err(err);
    }

    if is_materialized(&target, &stamp) {
        let _ = fs::remove_dir_all(&stage);
        return Ok(target);
    }
    if target.exists() {
        let _ = fs::remove_dir_all(&target);
    }
    match fs::rename(&stage, &target) {
        Ok(()) => Ok(target),
        Err(err) => {
            if is_materialized(&target, &stamp) {
                let _ = fs::remove_dir_all(&stage);
                Ok(target)
            } else {
                let _ = fs::remove_dir_all(&stage);
                Err(format!(
                    "rename {} -> {}: {err}",
                    stage.display(),
                    target.display()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_contains_missions_and_materializes_idempotently() {
        assert!(
            embedded_file_count() >= 100,
            "expected >= 100 embedded catalog files, got {}",
            embedded_file_count()
        );
        assert_eq!(EMBEDDED_CATALOG_SHA256.len(), 64);
        assert!(embedded_file("skills/ship-it/SKILL.md").is_some());
        assert!(embedded_file("runtime/providers/capabilities.json").is_some());
        assert!(embedded_file("runtime/quarantine.json").is_some());
        assert!(embedded_file("open_fleet/ui_assets/index.html").is_some());

        let tmp = env::temp_dir().join(format!("of-embedded-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let dir1 = materialize_catalog(Some(&tmp), "0.7.0").expect("first materialize");
        let dir2 = materialize_catalog(Some(&tmp), "0.7.0").expect("second materialize");
        assert_eq!(dir1, dir2);
        assert!(dir1.join("skills/review-it/SKILL.md").is_file());
        assert!(dir1.join("runtime/quarantine.json").is_file());
        assert!(dir1.join(STAMP_FILE).is_file());
        let _ = fs::remove_dir_all(&tmp);
    }
}
